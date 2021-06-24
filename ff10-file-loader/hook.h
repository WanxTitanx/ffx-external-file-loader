#pragma once
#include <filesystem>
#include <vector>

namespace ff10
{

	class FileLoader
	{
	public:
		static bool testPatchesHooks();
		static bool initPatchesHooks();
		static void setModulePath(const std::filesystem::path& path);
		static void setModuleBase(const intptr_t base);
		static void readConfig();

	private:
		//original functions to call in hooks
		using openVBFType = int (__thiscall *)(void* thisPtr, char* filename);
		using checkExistsType = int(__thiscall*)(void* thisPtr, char* filename);
		static constexpr intptr_t openVBFX = (0x61C0D0-0x400000);
		static constexpr intptr_t openVBFX2 = (0x942BA0 - 0x400000);
		static constexpr intptr_t checkExistsX = (0x6DC000 - 0x4C0000);
		static constexpr intptr_t checkExistsX2 = (0x942AD0 - 0x400000);

		//addresses of calls to hook
		static constexpr intptr_t OPENVBFBEFOREX = (0x6081AF - 0x400000);
		static constexpr intptr_t OPENVBFAFTERX = (0x6081B8 - 0x400000);
		static constexpr intptr_t OPENVBFX = (0x6081B3 - 0x400000);
		static constexpr intptr_t CHECKEXISTSX = (0x6C805F - 0x4C0000);
		static constexpr intptr_t CHECKVBFX = (0x7397AE - 0x4C0000);

		static constexpr intptr_t OPENVBFBEFOREX2 = (0x89134F - 0x400000);
		static constexpr intptr_t OPENVBFAFTERX2 = (0x891358 - 0x400000);
		static constexpr intptr_t OPENVBFX2 = (0x891353 - 0x400000);
		static constexpr intptr_t CHECKEXISTSX2 = (0x8911EF - 0x400000);
		static constexpr intptr_t CHECKVBFX2 = (0x494C6E - 0x400000);

		//hook functions
		static int __thiscall openVBFHook(void* thisPtr, int readAccess, int* result, char* path);
		static int __thiscall openCheckExistsHook(void* thisPtr, char* path);


		//helper functions

		struct tHookInit
		{
			const char* name;
			const intptr_t callPtr;
			const intptr_t hookPtr;
			const uint8_t original[5];
		};
		static const std::vector<tHookInit> _allHooksFFX;
		static const std::vector<tHookInit> _allHooksFFX2;

		struct tPatchBytes
		{
			const char* name;
			const intptr_t addr;
			const std::vector<uint8_t> patch;
			const std::vector<uint8_t> original;
		};
		static const std::vector<tPatchBytes> _allPatchesFFX;
		static const std::vector<tPatchBytes> _allPatchesFFX2;

		static std::filesystem::path modulePath;
		static intptr_t moduleBase;
		static std::vector<std::filesystem::path> modsPaths;
		static bool logAccess;
		static bool allowNoVbf;
		
		enum class eExecType
		{
			eFFX,
			eFFX2,
			eUnknown
		};
		static eExecType execType;
		static void testGameVersion();
	};
}
