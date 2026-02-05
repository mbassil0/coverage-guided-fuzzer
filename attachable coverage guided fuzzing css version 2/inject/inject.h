#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

bool LoadLibraryInjection(const char *sProcessName, const char *sDllPath);