#pragma once

#define VER_MAJOR 1
#define VER_MINOR 1
#define VER_STEP 3

#define _STRVERHELP(val) #val
#define _STRVER(val) _STRVERHELP(val)
#define STRVER _STRVER(VER_MAJOR) "." _STRVER(VER_MINOR) "." _STRVER(VER_STEP)
