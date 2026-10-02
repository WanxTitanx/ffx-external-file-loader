#include "pch.h"
#include "hook.h"
#include "profile_runtime.h"

namespace ff10
{
	std::filesystem::path FileLoader::modulePath;
	intptr_t FileLoader::moduleBase = 0;
	std::vector<std::filesystem::path> FileLoader::modsPaths = { "data/mods" };
	bool FileLoader::logAccess = false;
	bool FileLoader::allowNoVbf = false;
	bool FileLoader::enabled = false;
	const profiles::Profile* FileLoader::activeProfile = nullptr;
	FileLoader::eExecType FileLoader::execType = eExecType::eUnknown;
	bool FileLoader::testPatchesHooks()
	{
		testGameVersion();
		return activeProfile != nullptr;
	}

	bool FileLoader::initPatchesHooks()
	{
		if (!enabled) { LOG(INFO) << "File loader disabled; set General/enabled=1 to opt in."; return false; }
		if (!testPatchesHooks()) { LOG(ERR) << "Unsupported, modified or conflicting executable; no file patches installed."; return false; }
		const auto& p = *activeProfile;
		std::array<PatchWrite,5> writes{};
		writes[0] = {p.sites[0].rva,4,{0x53,0xFF,0x75,0x0C,0}};
		writes[1] = {p.sites[1].rva,5,{0xE8,0,0,0,0}};
		writes[2] = {p.sites[2].rva,2,{0xEB,0x79,0,0,0}};
		writes[3] = {p.sites[3].rva,5,{0xE8,0,0,0,0}};
		writes[4] = {p.sites[4].rva,2,{0xEB,0x70,0,0,0}};
		const std::uint32_t openDelta = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&FileLoader::openVBFHook) - (moduleBase+p.sites[1].rva+5));
		const std::uint32_t existsDelta = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&FileLoader::openCheckExistsHook) - (moduleBase+p.sites[3].rva+5));
		std::memcpy(writes[1].replacement.data()+1,&openDelta,4);
		std::memcpy(writes[3].replacement.data()+1,&existsDelta,4);
		if (!ApplyPatchTransaction(moduleBase,p,writes.data(),allowNoVbf?5:4)) {
			LOG(ERR) << "File-loader patch transaction rejected; no partial installation admitted.";
			return false;
		}
		LOG(INFO) << "File loader ready: " << p.name << "; native byte/callee witnesses and file SHA-256 verified.";
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
		enabled = GetPrivateProfileIntW(L"General", L"enabled", 0, configPath.c_str()) == 1;
		if (GetPrivateProfileStringW(L"General", L"allowNoVbf", L"false", buffer, _countof(buffer), configPath.c_str()))
		{
			if (std::wstring(buffer) == L"true")
				allowNoVbf = true;
		}
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
		if (!activeProfile || !path || !*path) return 10;
		openVBFType openVBFModule = (openVBFType)(activeProfile->openVbf + moduleBase);
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
		if (!activeProfile || !path || !*path) return 0;
		checkExistsType checkExistsModule = (checkExistsType)(activeProfile->checkExists + moduleBase);
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
		return checkExistsModule(thisPtr, path);
	}

	void FileLoader::testGameVersion()
	{
		activeProfile = SelectVerifiedProfile(static_cast<std::uintptr_t>(moduleBase));
		execType = !activeProfile ? eExecType::eUnknown : (activeProfile->x2 ? eExecType::eFFX2 : eExecType::eFFX);
	}

}
