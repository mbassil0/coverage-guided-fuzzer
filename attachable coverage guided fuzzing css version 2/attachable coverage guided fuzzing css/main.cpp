#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>


#include <fstream>

#include "debugger.h"
#include "fuzzer.h"

#include <process.h>

#include "helper_functions.h"

/*



Usage of the fuzzer:
	1. Put the modules that you want coverage on Release\fuzzer data\program\  where program must be the same name as the executable for ex srcds.exe then progrma must be srcds
	2. Run the harness


*/





uint8_t* res = nullptr;







size_t g_it_ctr = 0; //the global iteration counter for all threads



static HANDLE FindProcessHandle(const char *szProcessName)
{
	DWORD aProcesses[4096], dwNumberOfProcesses, dwBytesReturned;
	EnumProcesses(aProcesses, sizeof(aProcesses), &dwBytesReturned);

	dwNumberOfProcesses = dwBytesReturned / sizeof(DWORD);
	for (DWORD i = 0; i < dwNumberOfProcesses; i++)
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
			FALSE, aProcesses[i]);

		if (hProcess != NULL)
		{
			char sNameOfCurrentProcess[MAX_PATH];//dans GetModuleBaseName pas besoin de diviser(le troisieme param)vu que j'utilise char, si j'utilisais unicode je devrais diviser vu que c'est size en nombre de charactères
			if (!GetModuleBaseNameA(hProcess, NULL, sNameOfCurrentProcess, sizeof(sNameOfCurrentProcess)))
				//printf("failed %d", GetLastError());
				continue;

			if (!strcmp(szProcessName, sNameOfCurrentProcess))
				return hProcess;
			//printf("%s \n", sNameOfCurrentProcess);
		}

		CloseHandle(hProcess);
	}
	return NULL;
}






//todo benchmark tout voir ou je perds du temps
void run_on_loop_mode(void* args)
{
	/*
	With this function the data is mutated on the harness (the harness is a while loop that mutates the data and calls the parser continually)
	je devrai faire un autre debugger_loop_mode qui herite de debugger et qui reimplemente run_dbugger
	*/
	size_t thread_number = *(size_t*)args;
	printf("it's thread %d ! \n ", thread_number);
	srand(0x1337 ^ thread_number); //initializes the seed for when we are going to mutate the input
	debugger dbg;
	if (thread_number == 1)
		dbg.set_debugger_to_master();

	std::string shared_buffer_name = "Local\\fuzzer" + std::to_string(thread_number);

	
	
	printf("%s \n ", shared_buffer_name.c_str());
	const size_t buf_size = 8;
	//HANDLE h = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, buf_size, shared_buffer_name.c_str()); //we create the shared buffer to share with the harness			  
	//uint8_t *shared_buffer = (uint8_t*)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, buf_size);
	HANDLE h;	 
	uint8_t *shared_buffer = create_shared_buffer(shared_buffer_name, buf_size, &h );
	memset(shared_buffer, 0, buf_size);
	//const char harness_path[MAX_PATH] = "C:\\Users\\b\\source\\repos\\fuzzer_test\\Release\\fake harness.exe";
	const char harness_path[MAX_PATH] = "C:\\Users\\b\\source\\repos\\coverage guided fuzzer\\Release\\harness.exe";

	printf("param is %s \n", std::to_string(thread_number).c_str());



	while (1)
	{
	
		HANDLE proc_handle = FindProcessHandle("srcds.exe");
		if (proc_handle == NULL)
		{
			printf("failed to find the pid \n ");
		}
		

		if (DebugActiveProcess(GetProcessId(proc_handle)) == 0)
		{
			printf("debugactiveprocess failed error %d \n \n ", GetLastError());
			return;
		}


		DWORD exit_code;
		dbg.run_debugger_in_loop_mode(proc_handle, &exit_code, shared_buffer, buf_size, shared_buffer_name);

	}

	UnmapViewOfFile(shared_buffer);
	CloseHandle(h);
}



void run_threads_on_loop_mode(size_t number_of_threads_needed)
{
	for (size_t i = 0; i < number_of_threads_needed - 1; i++)
	{
		_beginthread(run_on_loop_mode, 0, &i);
		Sleep(1000);
		//run_on_loop_mode(i);
		//create one shared buffer per thread
	}

	run_on_loop_mode(&number_of_threads_needed); //on cree le dernier thread ici sinon on gaspille ce thread
}

//WaitForSingleObject(process_info.hProcess, INFINITE);








int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("use command line parameter to run the fuzzer! \n");
		//return 0;
	}



	run_threads_on_loop_mode(1);
	return 0;
}

