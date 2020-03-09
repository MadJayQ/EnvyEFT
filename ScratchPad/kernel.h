#pragma once

#include "ntops.h"

static const char* g_szKernelBaseName = "win32kbase.sys";


DWORD64 GetNTKernelModuleAddress(const char* moduleName);

