#pragma once
struct tVersion
{
	int major;
	int minor;
	int step;
};

extern "C" const char* FF10HgetName();
extern "C" tVersion FF10HgetVer();