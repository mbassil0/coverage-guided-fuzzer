#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>



typedef   int(_cdecl *fn) (const char *param);
void test_parser_harness(char *param);
void init(HINSTANCE hInstance, HINSTANCE a, LPSTR lpCmdLine, int nCmdShow);

void alloc_console()
{
	FILE* f;
	AllocConsole();
	freopen_s(&f, "CONIN$", "r", stdin);
	freopen_s(&f, "CONOUT$", "w", stdout);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)init, nullptr, 0, nullptr);
		break;






	}
	return TRUE;//voir diff entre return true et false
}






/*
how can i make this function behave the way i want thats what hackers think
*/


#include <chrono>
#include "detour_hooks.h"
#include "sdk.h"

CHookHandler detour;

typedef   bool(_cdecl *Fn)  (bool a, const char*b); //RE_RenderScene(const refdef_t *fd)
Fn OgCAppSystemGroup_InitSystems;



void bphere()
{
	printf("adding a breakpoint here  \n");
	__debugbreak();
}


bool done = false;
uint8_t *res = nullptr;

uint8_t *mutate_data(uint8_t* data_to_mutate, size_t data_length, size_t number_of_bytes_to_mutat, size_t *output_size)
{
	/*
		returns the mutated data
	*/
	

	if (res == nullptr) //on fait ça pour pas devoir alloc a chaque fois qu'on appelle mutate_dataattention si datalength change!
		res = (uint8_t*)malloc(data_length);

	*output_size = data_length;
	memcpy(res, data_to_mutate, data_length);

	for (size_t i = 0; i < number_of_bytes_to_mutat; i++)
	{
		size_t random_index = rand() % data_length;
		data_to_mutate[random_index] = rand() % 256;

	}

	return res;
}



bool write_data_to_fuzz_to_file(std::string map_to_fuzz_name, uint8_t *data_to_fuzz, size_t data_to_fuzz_size)
{
	/*
	writes the data the we will fuzz to  maps\to_fuz_thread_threadnumber.bsp
	*/



	std::string map_to_fuzz_path = "cstrike\\maps\\";
	map_to_fuzz_path += map_to_fuzz_name.c_str();


	DWORD bytes_written;
	HANDLE output_handle = CreateFile(map_to_fuzz_path.c_str(), FILE_GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (output_handle == INVALID_HANDLE_VALUE)
	{
		printf("generate_input: failed to open %s \n", map_to_fuzz_path.c_str());
		return false;
	}


	if (WriteFile(output_handle, data_to_fuzz, data_to_fuzz_size, &bytes_written, NULL) == 0)
	{
		printf("generate_input: WriteFile failed error: %d \n ", GetLastError());
		Sleep(99999);
		CloseHandle(output_handle);
		return false;
	}


	//free(mutated_data);
	CloseHandle(output_handle);
	return true;
}

uint8_t *get_initial_input(const char*file_to_open, size_t *original_size)
{
	DWORD size;
	HANDLE input_handle = CreateFile(file_to_open, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (input_handle == INVALID_HANDLE_VALUE)
	{
		printf("failed to open %s \n", file_to_open);
		return false;
	}

	size = GetFileSize(input_handle, NULL);
	if (size == INVALID_FILE_SIZE)
	{
		printf("GetFileSize failed \n");
		return false;
	}

	DWORD bytes_read;
	uint8_t *map_input = (uint8_t*)malloc(size);

	if (!ReadFile(input_handle, map_input, size, &bytes_read, NULL))
	{
		printf("ReadFile failed error: %d \n", GetLastError());
		CloseHandle(input_handle);
		return false;
	}

	printf("\n \n original size %d \n \n", size);
	CloseHandle(input_handle);


	*original_size = size;
	return map_input;
}




uint8_t *get_shared_buffer(std::string shared_buffer_name, size_t buffer_size)
{
	//LPSTR thread_number = GetCommandLineA(); //vu qu'on injecte on utilise pas GetCommandLineA
	
	//std::string shared_buffer_name = "Local\\fuzzer1";
	//shared_buffer_name += thread_number;

	printf("opening the fuzzer %s  \n \n", shared_buffer_name.c_str());

	HANDLE h = OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, shared_buffer_name.c_str());
	if (h == NULL)
	{
		printf("couldn't get the shared_buffer error: %d \n ", GetLastError());
		Sleep(150000);
	}

	uint8_t *shared_buffer = (uint8_t*)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, buffer_size);

	if (shared_buffer == 0)
	{
		printf("get_shared_buffer: MapViewOfFile failed error: %d \n", GetLastError());
		Sleep(150000);
	}


	printf("we sharing the buffer %s \n ", shared_buffer_name.c_str());

	return shared_buffer;
}

HMODULE g_engine;
CModelLoader *modelloader = nullptr;
int val = 0;
size_t g_thread_number = 0;






void write_to_address(char *address, char* to_write, size_t size)
{
	//vu que memcpy_s est difficile a debug....
	//printf("write_to_address: writing at %p  cnav loadd: %p  \n ", address, (byte*)GetModuleHandle("server.dll") + 0x2F0569);

	for (int i = 0; i < size; i++)
	{
		*(address + i) = to_write[i];
	}
}


void q_nsprintf_hook(char *ch, unsigned int size, char *jsp, char *jsp2)
{
	printf("q_nsprintf_hook was called size: %d  %s    %s \n", size, jsp, ch);
	//char to_write[256] = "maps\\original_mysecondmap_og.nav";
	char to_write[256] = "maps\\test_mysecondmap_og.nav";
	write_to_address(ch, to_write, 250);

	//Sleep(4999);
}

const uint32_t ready_message = 0xDEAD0000; //message que le harness mais dnas le shared buffer quand le jeu est pret a etre fuzze



void run_fuzzer_for_nav_files()
{
	//this function fuzzes CNavMesh::Load
	
	

	void *cnavmesh_load = (byte*)GetModuleHandle("server.dll") + 0x002F04F0;
	void *ecx_addr = *(byte**)((byte*)GetModuleHandle("server.dll") + 0x592A20);

	int result = 0;



	size_t it = 0;
	size_t thread_number = 1;

	std::string shared_buffer_name = "Local\\fuzzer" + std::to_string(thread_number);


	uint8_t *shared_buffer = get_shared_buffer(shared_buffer_name, 8); //status buffer
	*(uint32_t*)shared_buffer = ready_message;


	//wait for size  tant que cest pas egla a
	//on attend que le fuzzer mette le size du buffer dans le shared buffer
	while (*(uint32_t*)shared_buffer == ready_message)
	{
		Sleep(100);
	}

	size_t original_nav_file_size = *(size_t*)shared_buffer;
	 
	uint8_t *second_shared_buffer = get_shared_buffer(shared_buffer_name + 'b', original_nav_file_size); //le buffer avec lequel on va communiquer les données
	 
	uint8_t *map_buffer = (byte*)malloc(original_nav_file_size); //obliger de faire ca sinon ca reste stuck quand j'appelle cnavmesh_load jsp pq 
	
	printf("we received %d as size from the debugger \n ", original_nav_file_size);



	Sleep(3000);


	while (1)
	{
		
		shared_buffer[0] = 'R'; 
		

		printf("waiting for fuzzer to generate input..." );

		//on attend que le fuzzer prepare l'input et la mette dans second shared buffer
		while (shared_buffer[0] == 'R')
		{
			Sleep(1);
		}

		
		memcpy_s(map_buffer, original_nav_file_size, second_shared_buffer, original_nav_file_size);

		//original_nav_file_size
		if (write_data_to_fuzz_to_file("test_mysecondmap_og.nav", map_buffer, original_nav_file_size) == false) //original_nav_file_size
		{
			printf("generate input failed \n");
			return;
		}
		
		printf(" input was generated we are starting the iteration..... ");


		_asm mov ecx, ecx_addr
		_asm call cnavmesh_load
		_asm mov result, eax

		//if(it%100 == 1)
		printf("\n it: %d cnavmes laod returned: %p  \n", it, result);



		//indique qu'on a fini de preparer les donnees a fuzz
		shared_buffer[0] = 'E';

		

		//printf(" shared buffer is set to 1 ");

	
		//on attendque l'harness ait pris en compte que l'iterationest finie
		while (shared_buffer[0] == 'E') 
			Sleep(1);
	
		it++;

		printf("iteratoin completed succesfully \n");
	}

}



void __declspec (naked)  on_css_initialization_done(void *pInstance, const char *pStartupModName)
{


	//val = OgCAppSystemGroup_InitSystems(pInstance, pStartupModName);
	//OgCAppSystemGroup_InitSystems(pInstance, pStartupModName);
	_asm {pushad}



	//RunFuzzer();
	run_fuzzer_for_nav_files();

	_asm
	{
		popad
		retn
	}

	//on doit call original et pas faire pcq on a modifie les bytes retn...
}




void *import_function(const char* dll_name, const char *function_name)
{
	HMODULE dll = LoadLibrary(dll_name);
	if (!dll)
	{
		printf("couldn't find the dll: %s \n", dll_name);
		return nullptr;
	}

	printf("dll %p \n", dll);
	return GetProcAddress(dll, function_name);
}







typedef   int(_cdecl *dedicatedmainfn) (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
//typedef   model_t*(_thiscall GetModelForNameFn(const char *name, int referencetype);

/*
bytepatch some annoying parts
*/
void bytepatch()
{
	DWORD old;
	HMODULE ded = LoadLibrary("dedicated.dll");
	byte* addr = (byte*)ded + 0x0003D79;

	VirtualProtect(addr, 1024, PAGE_EXECUTE_READWRITE, &old);
	addr[0] = 0x90;
	addr[1] = 0x90;
	addr[2] = 0x90;
	addr[3] = 0x90;
	addr[4] = 0x90;


	ded = LoadLibrary("bin\\engine.dll");
	addr = (byte*)ded + 0x1FDFD8;




}


void sleep_until_key_is_hit()
{
	while (GetAsyncKeyState(VK_F7) == 0)
		Sleep(100);
}




void init(HINSTANCE hInstance, HINSTANCE a, LPSTR lpCmdLine, int nCmdShow)
{

	//HMODULE tier0 = LoadLibraryEx("tier0.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);;


	alloc_console();

	
	HMODULE engine = LoadLibrary("bin\\engine.dll");


	while (!(byte*)LoadLibrary("server.dll"))
		Sleep(100);

	printf("test server.dll: %p   \n", (byte*)LoadLibrary("server.dll") );



	//bytepatch(); cetait que utilise pr le fuzzer qui lancait from scratch ca je pense
	//on hook eng->Load() (CEngine::Load) je crois. apres que 0x1ffa0 ait été appelé dans CModAppSystemGroup::Main
	//OgCAppSystemGroup_InitSystems = (Fn)detour.detour((byte*)LoadLibrary("bin\\engine.dll")+0x1FFAF0, on_css_initialization_done);


	detour.detour((byte*)LoadLibrary("server.dll") + 0x158980, on_css_initialization_done);

	modify_call_instruction((byte*)LoadLibrary("server.dll") + 0x002F056A, q_nsprintf_hook); //pcq q_nsprintf crash dans cnav::load quand je veux fuzz
	modify_call_instruction((byte*)LoadLibrary("server.dll") + 0x2EEF12, q_nsprintf_hook);    //meme chose qu'en haut mais dans bspgetfilename
	//detour.detour((byte*)LoadLibrary("bin\\engine.dll") + 0x1A1110, on_css_initialization_done);

	//bphere();
	
}