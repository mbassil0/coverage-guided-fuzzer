#include "inject.h"

static HANDLE FindProcessHandle(const char *szProcessName)
{
	DWORD aProcesses[4096], dwNumberOfProcesses, dwBytesReturned;
	EnumProcesses(aProcesses, sizeof(aProcesses), &dwBytesReturned);

	dwNumberOfProcesses = dwBytesReturned / sizeof(DWORD);
	for (DWORD i = 0; i < dwNumberOfProcesses; i++)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
			FALSE, aProcesses[i]);

		if (hProcess != NULL)
		{
			char sNameOfCurrentProcess[MAX_PATH];//dans GetModuleBaseName pas besoin de diviser(le troisieme param)vu que j'utilise char, si j'utilisais unicode je devrais diviser vu que c'est size en nombre de charactères
			if (!GetModuleBaseNameA(hProcess, NULL, sNameOfCurrentProcess, sizeof(sNameOfCurrentProcess)))
				printf("GetModuleBaseName failed %d \n", GetLastError());


			if (!strcmp(szProcessName, sNameOfCurrentProcess))
				return hProcess;
			//printf("%s \n", sNameOfCurrentProcess);
		}

		CloseHandle(hProcess);
	}
	return NULL;
}

//from richter windows programming
bool LoadLibraryInjection(const char *sProcessName, const char *sDllPath)
{

	HANDLE hProcess = FindProcessHandle(sProcessName);
	if (!hProcess)
		return false;


	int cb = (1 + lstrlenA(sDllPath)) * sizeof(char);

	PWSTR pszLibFileRemoteAddr = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
	if (!pszLibFileRemoteAddr)
		return false;

	if (!WriteProcessMemory(hProcess, pszLibFileRemoteAddr, (PVOID)sDllPath, cb, NULL))
	{
		printf("LoadLibraryInjection WPM failed error %d \n ", GetLastError());
		return false;
	}



	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA"); //PAS OUBLIE DE CHANGER LE LOADLIBRARYA /LOADLIBRARYW SELON MES BESOINS
	if (!pfnThreadRtn)
		return false;

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemoteAddr, 0, NULL);
	if (hThread == NULL)
		return false;



	WaitForSingleObject(hThread, INFINITE); //on attend que le thread se finisse ici je crois


	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pszLibFileRemoteAddr, cb, MEM_RELEASE); //je ne pense pas que ça marche mais bon pas grave
	CloseHandle(hProcess);
	printf("yea");
	return true;
}
