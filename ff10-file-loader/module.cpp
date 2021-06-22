#include "pch.h"
#include "module.h"
#include "version.h"

const char* FF10HgetName()
{
	static const char moduleName[] = "FFX External File Loader by ffgriever";
	return moduleName;
}

tVersion FF10HgetVer()
{
	return {VER_MAJOR, VER_MINOR, VER_STEP};
}
