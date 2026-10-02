#pragma once
#include <filesystem>
#include <vector>
#include "profiles.h"

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
		static bool isEnabled() { return enabled; }
		friend struct FileLoaderTestAccess;

	private:
		//original functions to call in hooks
		using openVBFType = int (__thiscall *)(void* thisPtr, char* filename);
		using checkExistsType = int(__thiscall*)(void* thisPtr, char* filename);
		static const profiles::Profile* activeProfile;
		static bool enabled;

		//hook functions
		static int __thiscall openVBFHook(void* thisPtr, int readAccess, int* result, char* path);
		static int __thiscall openCheckExistsHook(void* thisPtr, char* path);


		//helper functions

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
