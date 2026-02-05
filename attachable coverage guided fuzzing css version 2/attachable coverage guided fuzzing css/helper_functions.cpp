#include "helper_functions.h"



uintptr_t get_module_base(DWORD processId, const CHAR *szModuleName)
{
	DWORD moduleBase = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &moduleEntry)) {
			do {
				if (strcmp(moduleEntry.szModule, szModuleName) == 0) {
					moduleBase = (DWORD)moduleEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnapshot, &moduleEntry));
		}
		CloseHandle(hSnapshot);
	}
	return moduleBase;
}


uint8_t *create_shared_buffer(std::string buffer_name, size_t size, HANDLE *h)
{
	/*
	On cree un deuxieme shared buffer dans lequelle le fuzzer mettra mutated data dedans
	le premier fuzzer servira juste à donner le state du fuzzer  le deuxieme se charge de communiquer les données
	*/

	

	*h = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, buffer_name.c_str()); //we create the shared buffer to share with the harness			  
	uint8_t *res = (uint8_t*)MapViewOfFile(*h, FILE_MAP_ALL_ACCESS, 0, 0, size);
	printf("creating a shared buffer with name: %s  %p\n", buffer_name.c_str(), res);
	return res;
}
