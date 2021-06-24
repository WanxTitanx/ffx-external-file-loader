#include "pch.h"
#include "hook.h"

namespace ff10
{
	std::filesystem::path FileLoader::modulePath;
	intptr_t FileLoader::moduleBase = 0;
	std::vector<std::filesystem::path> FileLoader::modsPaths = { "data/mods" };
	bool FileLoader::logAccess = false;
	FileLoader::eExecType FileLoader::execType = eExecType::eUnknown;
	const std::vector<FileLoader::tHookInit> FileLoader::_allHooksFFX = {
		{"hookOpenVBF", FileLoader::OPENVBFX, (intptr_t)&FileLoader::openVBFHook, {0x00, 0x89, 0x43, 0x04, 0x85}},
		{"hookCheckExists", FileLoader::CHECKEXISTSX, (intptr_t)&FileLoader::openCheckExistsHook, {0xE8, 0x9C, 0x3F, 0x01, 0x00}}
	};
	const std::vector<FileLoader::tPatchBytes> FileLoader::_allPatchesFFX = {
		{"patchOpenVBFBefore", FileLoader::OPENVBFBEFOREX, {0x53, 0xFF, 0x75, 0x0C}, {0xE8, 0x1C, 0x3F, 0x01}}, //push ebx, push [ebp+0xc]
		{"patchOpenVBFAfter", FileLoader::OPENVBFAFTERX, {0xEB, 0x79}, {0xC0, 0x75}} //jmp return
	};

	const std::vector<FileLoader::tHookInit> FileLoader::_allHooksFFX2 = {
		{"hookOpenVBF", FileLoader::OPENVBFX2, (intptr_t)&FileLoader::openVBFHook, {0x00, 0x89, 0x43, 0x04, 0x85}},
		{"hookCheckExists", FileLoader::CHECKEXISTSX2, (intptr_t)&FileLoader::openCheckExistsHook, {0xE8, 0xDC, 0x18, 0x0B, 0x00}}
	};
	const std::vector<FileLoader::tPatchBytes> FileLoader::_allPatchesFFX2 = {
		{"patchOpenVBFBefore", FileLoader::OPENVBFBEFOREX2, {0x53, 0xFF, 0x75, 0x0C}, {0xE8, 0x4C, 0x18, 0x0B}}, //push ebx, push [ebp+0xc]
		{"patchOpenVBFAfter", FileLoader::OPENVBFAFTERX2, {0xEB, 0x79}, {0xC0, 0x75}} //jmp return
	};

	bool FileLoader::testPatchesHooks()
	{
		testGameVersion();
		if (execType == eExecType::eUnknown)
			return false;

		const auto& _allPatches = execType == eExecType::eFFX ? _allPatchesFFX : _allPatchesFFX2;
		const auto& _allHooks = execType == eExecType::eFFX ? _allHooksFFX : _allHooksFFX2;
		for (const auto& patch : _allPatches)
		{
			if (patch.original.size() && memcmp((void*)(patch.addr+moduleBase), patch.original.data(), patch.original.size()) != 0)
			{
				LOG(ERR) << "Invalid original bytes for " << patch.name;
				return false;
			}
		}
		for (const auto& hook : _allHooks)
		{
			if (memcmp((void*)(hook.callPtr+moduleBase), hook.original, 5) != 0)
			{
				LOG(ERR) << "Invalid original bytes for " << hook.name;
				return false;
			}
		}
		return true;
	}

	bool FileLoader::initPatchesHooks()
	{
		if (!testPatchesHooks())
		{
			LOG(ERR) << "Invalid game version. Unable to find proper hook values.";
			return false;
		}

		const auto& _allPatches = execType == eExecType::eFFX ? _allPatchesFFX : _allPatchesFFX2;
		const auto& _allHooks = execType == eExecType::eFFX ? _allHooksFFX : _allHooksFFX2;

		HANDLE hProcess = GetCurrentProcess();

		for (const auto& patch : _allPatches)
		{
			if (!patch.patch.size()) continue;
			if (!WriteProcessMemory(hProcess, (LPVOID)(patch.addr+moduleBase), patch.patch.data(), patch.patch.size(), NULL))
			{
				LOG(ERR) << "Unable to write " << patch.name;
				return false;
			}
		}
		for (const auto& hook : _allHooks)
		{
			intptr_t hookAddr = intptr_t(hook.hookPtr);
			uint8_t callType = 0xe8;
			int32_t callRelativeAddr = int32_t(hookAddr - (hook.callPtr + moduleBase + 5));
			LOG(INFO) << "Addr: " << std::hex << callRelativeAddr << ", " << hookAddr << ", " << hook.callPtr + moduleBase;
			if (!WriteProcessMemory(hProcess, (LPVOID)(hook.callPtr + moduleBase + 0), &callType, 1, NULL)
				|| !WriteProcessMemory(hProcess, (LPVOID)(hook.callPtr + moduleBase + 1), &callRelativeAddr, 4, NULL))
			{
				LOG(ERR) << "Unable to write " << hook.name;
				return false;
			}
		}
		return true;
	}

	void FileLoader::setModulePath(const std::filesystem::path& path)
	{
		modulePath = path;
	}

	void FileLoader::setModuleBase(const intptr_t base)
	{
		moduleBase = base;
	}

	void FileLoader::readConfig()
	{
		std::wstring configPath = modulePath / "config" / "ff10-file-loader.ini";
		wchar_t buffer[512];
		if (GetPrivateProfileStringW(L"Logging", L"logAccess", L"false", buffer, _countof(buffer), configPath.c_str()))
		{
			if (std::wstring(buffer) == L"true")
				logAccess = true;
		}
		if (GetPrivateProfileStringW(L"Paths", nullptr, nullptr, buffer, _countof(buffer), configPath.c_str()))
		{
			modsPaths.clear();
			wchar_t* key = buffer;
			while (true)
			{
				wchar_t pathBuffer[1024];
				if (GetPrivateProfileStringW(L"Paths", key, nullptr, pathBuffer, _countof(pathBuffer), configPath.c_str()))
				{
					std::filesystem::path path(pathBuffer);
					if (path.is_relative())
						modsPaths.push_back(/*L".." / */path);
					else
						modsPaths.push_back(path);
				}
				key += wcslen(key) + 1;
				if (*key == 0)
					break;
			}
		}
		if (!modsPaths.size())
			modsPaths.push_back(L"data/mods");
	}

	/**
	* filename is normalized at this point to use slashes
	*/
	int __thiscall FileLoader::openVBFHook(void* thisPtr, int readAccess, int* result, char* path)
	{
		openVBFType openVBFModule = (openVBFType)((execType == eExecType::eFFX ? openVBFX : openVBFX2) + moduleBase);
		try
		{
			std::string filename(path);
			if (filename.substr(0, 9) == "../../../")
				filename = filename.substr(9);
			else if (filename.substr(0, 8) == "../../..")
				filename = filename.substr(8);
			else if (filename[0] == '/')
				filename = filename.substr(1);


			for (auto pathIt = modsPaths.cbegin(); pathIt != modsPaths.cend(); ++pathIt)
			{
				const auto filePath = *pathIt / filename;
				if (std::filesystem::exists(filePath))
				{
					if (logAccess) LOG(INFO) << "Reading DIR: " << filePath.string();
					result[1] = 0;
					if (readAccess)
					{
						result[0] = (int)CreateFileW(filePath.wstring().c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
						if (result[0] != -1)
							return 0;
					} else
					{//not sure yet whether it actually ever reaches this, seems to be a bit weird, but lets keep it the way the game does for now
						result[0] = (int)CreateFileW(filePath.wstring().c_str(), FILE_WRITE_DATA, 0, NULL, OPEN_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
						if (result[0] != -1)
							return 0;
						result[0] = (int)CreateFileW(filePath.wstring().c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
						if (result[0] != -1)
						{
							CloseHandle((HANDLE)result[0]);
							result[0] = -1;
							return 12;
						}
					}
					return 10;
				}
			}

			if (logAccess) LOG(INFO) << "Reading VBF: " << filename;
		}
		catch (...)
		{
		}
		result[1] = openVBFModule(thisPtr, path);
		return 0;
	}

	int __thiscall FileLoader::openCheckExistsHook(void* thisPtr, char* path)
	{
		openFMVType openFMVModule = (openFMVType)((execType == eExecType::eFFX ? checkExistsX : checkExistsX2) + moduleBase);
		try
		{
			std::string filename(path);
			if (filename.substr(0, 9) == "../../../")
				filename = filename.substr(9);
			else if (filename.substr(0, 8) == "../../..")
				filename = filename.substr(8);
			else if (filename[0] == '/')
				filename = filename.substr(1);


			for (auto pathIt = modsPaths.cbegin(); pathIt != modsPaths.cend(); ++pathIt)
			{
				const auto filePath = *pathIt / filename;
				if (std::filesystem::exists(filePath))
				{
					if (logAccess) LOG(INFO) << "Exists DIR: " << filePath.string();
					return 1;
				}
			}

			if (logAccess) LOG(INFO) << "Exists VBF: " << filename;
		}
		catch (...)
		{
		}
		return openFMVModule(thisPtr, path);
	}

	void FileLoader::testGameVersion()
	{
		if (_allPatchesFFX[0].original.size() && memcmp((void*)(_allPatchesFFX[0].addr + moduleBase), _allPatchesFFX[0].original.data(), _allPatchesFFX[0].original.size()) == 0)
		{
			execType = eExecType::eFFX;
			LOG(INFO) << "FFX detected";
		} else if (_allPatchesFFX2[0].original.size() && memcmp((void*)(_allPatchesFFX2[0].addr + moduleBase), _allPatchesFFX2[0].original.data(), _allPatchesFFX2[0].original.size()) == 0)
		{
			execType = eExecType::eFFX2;
			LOG(INFO) << "FFX-2 detected";
		}
	}

}
