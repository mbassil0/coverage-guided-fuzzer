
#include <chrono>

#include "debugger.h"
#include "fuzzer.h"


#include <tlhelp32.h>
#include <Windows.h>

#include "helper_functions.h"
/*
use smart data structures and dotn copy paste rewrite it au pire


todo injecte un programme qui copie/ecrit memorty dans le programme super vite
tester si ça marche sur harness qui a loop infinie et ou harness laod le programe qu'on pause
mais harness est loop infinie tester sur ça test snapshot et file hook aussi
*/




void sleep_until_key_is_hit()
{
	while (GetAsyncKeyState(VK_F7) == 0)
		Sleep(100);
}

void kill_process(HANDLE proc)
{
	DWORD id = GetProcessId(proc);
	printf("id %d  error: %d", id, GetLastError());

	if (DebugActiveProcessStop(id) == 0)
		printf("kill_process: DebugActiveProcessStop failed %d \n ", GetLastError());

	HANDLE p = OpenProcess(PROCESS_TERMINATE | PROCESS_ALL_ACCESS, FALSE, id);

	if (TerminateProcess(p, 0) == 0)
		printf("kill_process: TerminateProcess worked  error: %d \n", GetLastError());
	else
		printf("kill_process failed ERROR: %d \n ", GetLastError());

	CloseHandle(p);
}

void handle_post_mortem(LPDEBUG_EVENT debug_event)
{
	/*
	permet de terminer le process correctement sinon le process ne se termine
	pas correctement en debug mode et donc on ne peut pas appeler createprocess une deuxieme fois
	le process meurt reellement que quand que le debug event est EXIT_PROCESS_DEBUG_EVENT
	*/

	int max_events_timeout = 100;

	while (max_events_timeout > 0)  //&& debug_event->dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT
	{

		if (WaitForDebugEvent(debug_event, 100) && GetLastError() == ERROR_SEM_TIMEOUT)
			continue;

		ContinueDebugEvent(debug_event->dwProcessId, debug_event->dwThreadId, DBG_CONTINUE);
		max_events_timeout--;
	}





}




bool has_fuzzing_began(uint8_t *shared_buffer, size_t shared_buffer_length)
{
	/*
	si le shared buffer est nul et qu'on a une exception ca veut dire que l'exception ne vient pas de nous
	vu qu'on a pas encore commence a fuzz donc on continue a run le programme
	*/
	size_t size_to_verify = min(shared_buffer_length, 5000);
	for (size_t i = 0; i < size_to_verify;)
	{

		if (shared_buffer[i] != 0)
			return true;
	}
	printf("ret false \n");
	//return m_it != 0;
	return false;
}


const uint32_t ready_message = 0xDEAD0000; //message que le harness mais dnas le shared buffer quand le jeu est pret a etre fuzze



debugger::debugger(HANDLE proc)
{
	m_proc = proc;
}

debugger::debugger()
{

}


void debugger::print_threads_eip()
{
	//todo print path of module
	for (auto const& thread_id : m_threads)
	{
		CONTEXT context;
		memset(&context, 0, sizeof(CONTEXT));
		context.ContextFlags = CONTEXT_ALL;

		if (GetThreadContext(m_threads[thread_id.first], &context) == NULL)// string (key)
			printf("prin_trheads_eip: GetThreadContext failed \n");

		uint8_t opcode_buffer[1];
		read_mem(context.Eip, opcode_buffer, 1);
		
		DWORD module_base_addr = (DWORD)get_module_base(GetProcessId(m_proc), (char*)filename_from_module_base((void*)context.Eip).c_str());

		printf("tid: %d Got eip %p  base address of module; %p in module %s  opcode at that eip: %02X \n", 
			m_threads[thread_id.first], context.Eip - module_base_addr, module_base_addr, filename_from_module_base((void*)context.Eip).c_str(), opcode_buffer[0]);
	}



}

bool debugger::write_mem(uintptr_t address, uint8_t *to_write, size_t size_of_data_to_write)
{
	if (WriteProcessMemory(m_proc, (void*)address, to_write, size_of_data_to_write, NULL) == 0)
		return false;
	else
		return true;
}

bool debugger::read_mem(uintptr_t address, uint8_t *out_buffer, size_t size_of_data_to_read)
{
	if (ReadProcessMemory(m_proc, (void*)address, out_buffer, size_of_data_to_read, NULL) == 0)
		return false;
	else
		return true;
}

bool debugger::flush_instruction_cache()
{
	/*Flushed all instruction for the process (notsure) */
	return FlushInstructionCache(m_proc, NULL, 0);
}

void debugger::add_breakpoint(uintptr_t address, std::string module_name, windows_module *new_module)
{

	uint8_t breakpoint_byte[1] = { 0xCC };
	uint8_t original_byte[1] = { 0 };

	
	if (new_module->breakpoints.find(address) != new_module->breakpoints.end())
	{
		printf("this breakpoint (addr %p module base addr %p ) already exists trying to add a breakpoint at the same address more than once! \n", address, new_module->module_base_address);;
		return;
	}

	if (!read_mem(address, original_byte, 1))
	{
		printf("add_breakpoint failed to read the original byte error: %p \n", GetLastError());
		return;
	}

	
	write_mem(address, breakpoint_byte, 1);
	if (new_module != nullptr)
		new_module->breakpoints.insert(std::pair<uintptr_t, breakpoint>(address, breakpoint(address, original_byte[0])));
	//printf("Adding a bp at %p  original byte was %02x eip was  \n", address, original_byte[0]);
}

bool debugger::remove_breakpoint(uintptr_t address, DWORD tid)
{

	std::string name = filename_from_module_base((void*)address);


	//we check if the breakpoint is one of ours (if it is in a module that we previously requested  to add breakpoints in)
	if (m_modules.find(name) == m_modules.end())
		return false;

	byte cur[1];
	read_mem(address, cur, 1);


	if (m_modules[name]->breakpoints.find(address) == m_modules[name]->breakpoints.end())
	{
		
		printf("remove_breakpoint: fatal error we are trying to remove a breakpoint that isn't amongst our bp list opcode : %02X  \n", cur[0]);
		Sleep(1999);
		return false;
	}

	//printf("removing bp setting eip at %p  original was %02X size of maps: %d    og: : %02X    ", m_modules[name]->breakpoints[address].m_address, m_modules[name]->breakpoints[address].m_original_byte, m_modules[name]->breakpoints.size(), cur[0]);

	uint8_t original_byte[1] = { m_modules[name]->breakpoints[address].m_original_byte };
	write_mem(address, original_byte, 1);
	flush_instruction_cache();


	CONTEXT context;
	memset(&context, 0, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_ALL;  //todo peut etre utiliser InitializeContext 

	if (is_32bit)
	{
		if (m_threads.find(tid) == m_threads.end())
		{
			m_threads[tid] = OpenThread(THREAD_ALL_ACCESS, 0, tid); //todo close it 
			printf("remove_breakpoints: adding thread % \n", tid);
		}
		
		if (GetThreadContext(m_threads[tid], &context) == NULL)
			printf("GetThreadContext failed error: %d \n", GetLastError());

		//printf("restoring the byte %p at addr %p  %p  \n", original_byte[0], m_modules[name].breakpoints[address].m_address, address);
		//printf(" addr:  %p eip:  %p   ", address, context.Eip);

		context.Eip -= 1;  //context.Eip = address; jsp le quel est correct edit presque sur que -=1 est correct

		//printf("%p  \n \n ", context.Eip);
		if (SetThreadContext(m_threads[tid], &context) == NULL)
			printf("SetThreadContext failed error %d \n", GetLastError());
	}

	m_modules[name]->breakpoints.erase(address);
	return true;
}


bool debugger::add_breakpoints_from_file(std::string module_name, uintptr_t base_address)
{
	/*
	Desc: ajoute les bp pour un certain module (qui a pour nom module_name) si ce module a un fichier des bp qu'on veut ajouter

	le format du fichier qui contient les breakpoints est simple
	pour un fichier 32 bit: c'est une suite de nombre de 4 bytes stocke en little endian
	pour un fichier 32 bit: c'est une suite de nombre de 8 bytes stocke en

	ex pour un fichier contenant 2 fois le chiffre 0x00118E5 ca nous donne:
	E5 18 01 00 E5 18 01 00


	todo appeller ca seulement a l'initialisation du programme avant le snapshot sinon on doit ajouter des bp pour rien
	ca fait perdre cpu time initialiser qu'une seule fois
	
	todo rename add_module_breakpoints_fro_file?
	*/
	if (module_name != "server.dll")
		return false;
	//std::string  bps_data_relative_path = "fuzzer data/fake harness/breakpoints_data/" + module_name + ".bp_data";
	//std::string  bps_data_relative_path = "fuzzer data/srcds/breakpoints_data/" + module_name + ".bp_data";
	std::string    bps_data_path  = m_bps_data_folder_path + module_name + ".bp_data";
	//bps_data_path = "C:\\Users\\b\\Desktop\\test_server.bp_data";
	std::ifstream  bps(bps_data_path.c_str(), std::ios::binary | std::ios::ate);

	if (bps.fail())
	{
		//printf("couldn't find the file: %s \n", module_name.c_str());
		return false;
	}

	/*
	TODO WRITE DESTRUCTOR AND DEALLOCATE m8MODULES !!!!!
	
	*/
	windows_module *new_module = new windows_module(module_name, base_address); //todo write destructor et deallocate //todo user smart ptr ?
	size_t file_size = bps.tellg();
	size_t size_to_read = 8;
	size_t i = 0;

	bps.seekg(0, std::ios::beg);
	

	if (is_32bit)
		size_to_read = 4;

	uint8_t *addr_of_where_to_place_bp = (uint8_t*)malloc(size_to_read);

	while (i < file_size)
	{
		bps.read((char*)addr_of_where_to_place_bp, size_to_read);
		uintptr_t cur_bp_addr = *(uintptr_t*)addr_of_where_to_place_bp + base_address;
		//printf("add breakpoints from file got %p base addr: %p\n", cur_bp_addr, base_address);
		add_breakpoint(cur_bp_addr, module_name, new_module);
		//printf("2nd: Adding a bp at %p  original byte was %02x eip was %p \n \n", new_module->breakpoints[cur_bp_addr].m_address, new_module->breakpoints[cur_bp_addr].m_original_byte, cur_bp_addr);
		i += size_to_read;
	}

	flush_instruction_cache();

	//todo prendre en compte bp double les supprimer sinon ça fait del ap lace prise pour rien
	printf("Got %p breakopints for module: %s \n", file_size / 4, module_name.c_str()); //c'est /4 car on est en 32 bit en 64bit c'est /8 car le fichier stock les bp sous forme de pointer de (32 ou 64) bytes

	free(addr_of_where_to_place_bp);
	bps.close();
	
	printf("last Adding a bp at %p  original byte was %02x number of bp: %d \n \n", new_module->breakpoints[ 0x03627FF+base_address].m_address, new_module->breakpoints[0x03627FF+base_address].m_original_byte, new_module->breakpoints.size());
	m_modules.insert(std::pair<std::string, windows_module*>(module_name, new_module));
	printf("aaa:  %d \n", m_modules["server.dll"]->breakpoints.size()); //output all keys de m
	for (const auto &d : m_modules) {
		std::cout << d.first << "\n";
		std::cout << m_modules[d.first]->breakpoints.size();
	}
	
	return true;
}


std::string debugger::filename_from_module_base(void* base_address)
{
	//toodo use getmappedfilenameW et use wchar
	char file_path[4096];
	char *filename;

	memset(file_path, 0, 4096);
	GetMappedFileName(m_proc, base_address, file_path, 512);
	size_t i = 4095;

	
	//vu qque getmappedfilename retourne le path on veut le file name donc on va enlever le path pour garder que le filename
	while (i > 0 && file_path[i] != '\\')
		i--;


	//should never happen
	if (i == 0)
	{
		printf("filename_from_module_base:  GetMappedFileName FAILED for address %p \n", base_address);
		return std::string("error");
	}

	else
		filename = (char*)file_path + i + 1;

	//printf("filename_from_module_base\n%s   \n%sa  \n \n ", file_path, filename);
	std::string res = filename;
	return res;
}


DWORD debugger::on_load_dll_debug_event(DEBUG_EVENT debug_event)
{
	//add brekapoints add breakpoints for module  nameofdll_dll.bpinfo
	/*std::string module_name = filename_from_module_base(debug_event.u.LoadDll.lpBaseOfDll);
	if (module_name == "engine.dll")
	{
		m_engine_base = (uintptr_t)debug_event.u.LoadDll.lpBaseOfDll;
		return 1;
	}



	add_breakpoints_from_file(module_name, (uintptr_t)debug_event.u.LoadDll.lpBaseOfDll);*/


	return 0;
}


void debugger::on_create_process_debug_eent(LPDEBUG_EVENT debug_event)
{	
	void *base_address = debug_event->u.CreateProcessInfo.lpBaseOfImage;
	std::string filename = filename_from_module_base(base_address);
	add_breakpoints_from_file(filename, (uintptr_t)base_address);
	//printf("got the base address  %p \n ", base_address);

	printf("%s \n", filename.c_str());
	
}

bool debugger::on_breakpoint_hit(LPDEBUG_EVENT debug_event, uint8_t* shared_buffer, DWORD tid)
{
	/*
	Returns true if one of our breakpoints was hit

	*/
	bool res = false;
	void *address = debug_event->u.Exception.ExceptionRecord.ExceptionAddress;
	uintptr_t address_base_0 = (uintptr_t)address - get_module_base(GetProcessId(m_proc), (char*)filename_from_module_base(address).c_str());

	//printf("a bp was hit on %s at address (base0): %p  address: %p  \n ", filename_from_module_base(address).c_str(), address_base_0, address);



	int  code = debug_event->u.Exception.ExceptionRecord.ExceptionCode;
	PVOID bp_address = debug_event->u.Exception.ExceptionRecord.ExceptionAddress;
	std::string module_name = filename_from_module_base((void*)bp_address);

	
	if (remove_breakpoint((uintptr_t)bp_address, tid)) //si c'est un de mes bp je le supprime pcq on va quand meme save les input qui permetter de prendre ce path la
	{
		//add_file_to_interesting_inputs
		//printf("was in the list for %s \n", filename);
		res = true;
	}

	return res;
}

bool debugger::on_acces_violation(LPDEBUG_EVENT debug_event, constantSizeDataManager *data_manager,  uint8_t *shared_buffer, bool has_fuzzing_started)
{
	/*
	Returns false if we caused the acces violation (was caused after we started fuzzing)
	if it was  caused by the program before we began fuzzing then we return true 
	*/

	uintptr_t eip_base_0 = (uintptr_t)debug_event->u.Exception.ExceptionRecord.ExceptionAddress - get_module_base(GetProcessId(m_proc), (char*)filename_from_module_base(debug_event->u.Exception.ExceptionRecord.ExceptionAddress).c_str());
	
	printf("got access violation at %p (%p)  in file %s \n", debug_event->u.Exception.ExceptionRecord.ExceptionAddress,
		eip_base_0,
		filename_from_module_base(debug_event->u.Exception.ExceptionRecord.ExceptionAddress).c_str());

	uint8_t buf[4];
	read_mem((uintptr_t)debug_event->u.Exception.ExceptionRecord.ExceptionAddress, buf , 4);
	//printf("%02X %02X %02X %02X  at address %p original was %02X", buf[0], buf[1], buf[2], buf[3], eip_base_0, m_modules["server.dll"]->breakpoints[(uintptr_t)debug_event->u.Exception.ExceptionRecord.ExceptionAddress].m_original_byte);

	//if (has_fuzzing_started)
	if(m_it > 0)
	{
		printf("and it matters \n");
		std::string file_name = "crash_"  + filename_from_module_base(debug_event->u.Exception.ExceptionRecord.ExceptionAddress) + std::to_string(eip_base_0);
		data_manager->dump_input_to_file(shared_buffer, file_name);
		return false;
	}
	else
	{
		
		return false;
	}
	

}


void debugger::handle_loop_mode(uint8_t *status_shared_buffer, uint8_t *second_shared_buffer, constantSizeDataManager *data_manager, bool *was_new_bp_hit_during_iteration)
{
	/*
	status buffer se charge de communiquer le status du fuzzer avec l'harness.
	second_shared_buffer communique les données
	*/
	
	
    // mon systeme doit pouvoir etre synch completement je dois pouvoir recuperer l'input pour save les bp
	static bool has_iteration_started = false;
	static auto start_time = std::chrono::steady_clock::now();

	//printf("%p   %d   \n ", status_shared_buffer[0], has_iteration_started);


	if (!has_iteration_started && status_shared_buffer[0] == 'R')
	{


		//this function needs a state is reading is doing car si je sleep dans cette fonction alors je ne peux pas sortir et remove les bp
		

		*was_new_bp_hit_during_iteration = false; //on met was_new_bp_hit_during_iteration pour la nouvelle iteration
		data_manager->mutate_data(m_number_of_bytes_to_mutate, second_shared_buffer);


		m_it++; //data_manager doit  etre des variables de la classe aussi les bp doivent rester quand on restart ceux qui sont partis doivent partier
				// on reajoute que les bp qui ont pas encore ete hit
		g_it_ctr++;

		std::chrono::duration<double> elapsed_seconds = std::chrono::steady_clock::now() - start_time;
		printf("sstarting iteration: it: %d  size: %d  we are running at: %f iterations/sec %d  \n", m_it, data_manager->m_data.size(), (double)m_it / elapsed_seconds.count(), status_shared_buffer[0]);
		//if (m_is_master_debugger&& g_it_ctr % 1000 == 1)  
		if (m_it % 1000 == 1)
		{

			
			

		}
		has_iteration_started = true;
		status_shared_buffer[0] = 'G'; //on indique a l'harness qu'on a genere l'input
	}



	//indique que harness a fini d'ecrire le fichier  (si on fait pas ca on risque d'appeler cette partie plusieurs fois)
	if (has_iteration_started == true && status_shared_buffer[0] == 'E')
	{
		has_iteration_started = false;
		status_shared_buffer[0] = '\x22'; //on indique a harness qu'on a pris en compte que l'iteration etait finie (on met x22 au hasard ca aurait pu etre nimporte quoi du moment que shared_buffer ne vaut plus \x11
		printf("ending iteration %d  \n ", m_it);
	}

}


bool debugger::run_debugger_in_loop_mode(HANDLE proc, DWORD *exit_code, uint8_t *shared_buffer, size_t shared_buffer_size, std::string first_shared_buffer_name)
{
	/*
	detects if the program crashed or if a new bp was reached
	called when we are fuzzing in loop mode in the harness if we are not in loop mode call run_debugger instead

	loop mode is when the harness runs in a loop and calls the function to fuzz in that loop until it crashes basically the harness does
	while(1)
		input = mutate_input ()
		fuzz_function(input)

	exit_code is filled only if it crashes  otherwises its value will be 0x1336



	first shared_buffer is also called status_shared_buffer and indicates the status 
	the second shared buffer contains the data that we fuzz

	*/


	DEBUG_EVENT debug_event;
	ZeroMemory(&debug_event, sizeof(debug_event));
	m_proc = proc;
	bool was_new_bp_hit_during_iteration = false;
	bool alive = true;



	//
	//configure the fuzzer here and in add_breakpoints_from_file (for the breakpoitns data path) et run_on_loop_mode
	//



	size_t original = 3000;
	constantSizeDataManager data_manager;
	
	//size_t it = 0; //voir deja si it est sync todo noter it dans sharedbuffer le premier byte ?

	
	const char original_map_name[] = "C:\\Users\\b\\source\\repos\\coverage guided fuzzer\\Release\\cstrike\\maps\\original\\original_mysecondmap_og.nav";
	//const char original_map_name[] = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Source\\cstrike\\\maps\\cs_militia.nav";
	data_manager.register_and_set_data_size_input_from_file(original_map_name, &original);
	m_bps_data_folder_path = "C:\\Users\\b\\source\\repos\\coverage guided fuzzer\\Release\\fuzzer data\\srcds\\breakpoints_data\\nav\\";


	//tres importer remettre m_number_of_bytes_to_mutate a une autre valeur que 0!
	m_number_of_bytes_to_mutate = 1; //todo changer mutation technique mutate 5 fois le file

	//
	//End of configuration
	//

	
	

	//we create the second shared buffer 
	HANDLE hsecond_shared_buffer;
	uint8_t *second_shared_buffer = create_shared_buffer(first_shared_buffer_name + 'b', data_manager.get_size(), &hsecond_shared_buffer);
	memset(second_shared_buffer, 0, data_manager.get_size());


	printf("waiting for harness to be ready... \n");


	
	

	while (alive)
	{
		BOOL der = WaitForDebugEvent(&debug_event, 2); //INFINITE et handle shared buffer dans autre thread ? vori c quoi le plus rapide dans benchmark  mais bp yaura pas dinfo sur hasbp been hit
		if (der == 0)
		{
			//si on a recu aucun event alors on s'occupe de fuzz (idee creer un nouveau thread pour ca?)
			if (GetLastError() == ERROR_SEM_TIMEOUT)
			{
				static bool has_been_initialised = false;


				
				
				
				
	

				//we wait untill the harness is ready to be fuzzed to initialize (adding the breakpoints and getting the second shared buffer)
				if (has_been_initialised == false && (*(uint32_t*)shared_buffer == ready_message))
				{
					//we are now ready to add the breakpoints and start fuzzing
					
					add_breakpoints_from_file("server.dll", get_module_base(GetProcessId(m_proc), "server.dll"));
				
					printf("shared size is %d \n ", data_manager.get_size());
					*(size_t*)shared_buffer = data_manager.get_size(); // on communique a l'harness le size des données qu'on veut fuzz
					
					printf("waiting for second shared buffer to be created .. \n");

			
					
					
					

					printf("got the second shared buffer %p  \n ", *(uint32_t*)second_shared_buffer);
					printf("size of shared buffer: %p  the harnes should be ready to be fuzzed now \n ", *(size_t*)shared_buffer);
					has_been_initialised = true;
				}
				
				else if (has_been_initialised == true)
				{
					handle_loop_mode(shared_buffer, second_shared_buffer, &data_manager, &was_new_bp_hit_during_iteration);
					
					//print_threads_eip();
					
				}



				//else if (has_been_initialised == false )
				//	printf("has been initialised %d %p \n", has_been_initialised, *(uint32_t*)shared_buffer);
				//


				continue; //oblige de faire ça sinon dans le cas ou on a un debug event il sera run plusieurs fois si on ne met pas le continue ici
			}
			//else
				//printf("WaitForDebugEvent got the error \n ", GetLastError());
		}

		
	




		size_t original = 3000;
		constantSizeDataManager data_manager;


			//note on est oblige d'ajouter les bp pour un fichier (càd appeler add_breakpoints_from_file) avant que le module 
			//ou on veut add les bp soit load càd on peut pas juste attacher a un process qui a deja load ce module 
			//et essayer d'ajouter les bp ca va crash




		

		switch (debug_event.dwDebugEventCode)
		{
		case CREATE_THREAD_DEBUG_EVENT:
			//m_threads[debug_event.dwThreadId] = debug_event.u.CreateThread.hThread;
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			m_threads[debug_event.dwThreadId] = debug_event.u.CreateProcessInfo.hThread;
			on_create_process_debug_eent(&debug_event);
			printf("CREATE_PROCESS_DEBUG_EVENT: loading %s  at address %p \n", filename_from_module_base(debug_event.u.CreateProcessInfo.lpBaseOfImage).c_str(), debug_event.u.CreateProcessInfo.lpBaseOfImage);
			break;


		case LOAD_DLL_DEBUG_EVENT:
			// Read the debugging information included in the newly 
			// loaded DLL. Be sure to close the handle to the loaded DLL 
			// with CloseHandle.

			//printf("LOAD_DLL_DEBUG_EVENT: loading %s  at address %p \n", filename_from_module_base(debug_event.u.LoadDll.lpBaseOfDll).c_str(), debug_event.u.LoadDll.lpBaseOfDll);
			on_load_dll_debug_event(debug_event);
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			//delete(m_modules[name]) on le delete puis ecrire destructor dans windows_module
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			printf("pocess terminated quitting... \n");
			*exit_code = 0; //todo on peut surement obtenit process code dans le debug event
			alive = false;
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			//printf("debug string: got %s \n", debug_event.u.DebugString.lpDebugStringData);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			if (m_threads.find(debug_event.dwThreadId) == m_threads.end())
				printf("trying to delete a tid of m_trheads that isn't in m_threads \n");
			else
				m_threads.erase(debug_event.dwThreadId);
			break;

		case EXCEPTION_DEBUG_EVENT:
			switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:

				if (on_breakpoint_hit(&debug_event, second_shared_buffer, debug_event.dwThreadId))
				{
					if (was_new_bp_hit_during_iteration == false) //pas besoin de save l'input actuelle plusieurs fois pour une iteration
					{
						data_manager.register_input(second_shared_buffer); // on a decouvert un nouveau chemi ndonc on save input
						//add bp name addres andm odule hit too add crash eip and module
						data_manager.dump_input_to_file(second_shared_buffer, "bp" + std::to_string(data_manager.get_size()));
					}
					was_new_bp_hit_during_iteration = true;	//aussi on est oblige de register_input ici car si on l'enregistre au moment ou on prepare la nouvelle iteration shared_buffer vaut \x13\x33\x33\x37
				}
				break;

			case EXCEPTION_ACCESS_VIOLATION:
				//ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);

				alive = on_acces_violation(&debug_event, &data_manager, shared_buffer, has_fuzzing_began(shared_buffer, shared_buffer_size));
				if(alive == false)
					*exit_code = EXCEPTION_ACCESS_VIOLATION; //ptet pas le bon code mais osef
				
			case 0x406D1388:
				//ca arrive quand on load tier0 jsp pqmais on peut l'ignorer
				break;

			default:
				// Handle other exceptions. 
				printf("unhandled exception code: %p occured code: %p on file  %s  \n", debug_event.u.Exception.ExceptionRecord.ExceptionCode, debug_event.u.Exception.ExceptionRecord.ExceptionAddress, filename_from_module_base(debug_event.u.Exception.ExceptionRecord.ExceptionAddress).c_str());
				*exit_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
				if (has_fuzzing_began(shared_buffer, shared_buffer_size))
				{
					if (m_it > 0)
					{
						alive = false;
						data_manager.dump_input_to_file(shared_buffer);
						printf("this unhandled exception was probably caused by our fuzzer \n \n");
					}
					
					uint8_t buf[4];
					read_mem((uintptr_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress, buf, 4);
				
					uintptr_t eip_base_0 = (uintptr_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress - get_module_base(GetProcessId(m_proc), (char*)filename_from_module_base(debug_event.u.Exception.ExceptionRecord.ExceptionAddress).c_str());
					printf("unhandled: %02X %02X %02X %02X  at address %p original: %02X \n", buf[0], buf[1], buf[2], buf[3], eip_base_0, m_modules["server.dll"]->breakpoints[(uintptr_t)debug_event.u.Exception.ExceptionRecord.ExceptionAddress].m_original_byte);
				
					alive = false;
				}


				//todo noter le file qui a fait crash dan sdump_input_to_file
				//sinon on peut eventuellement garder copie de input dans data manager cur_input
				//should probalby save inputs to files when it crashes tbh in a new folder for the crash
				//ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);										    

				break;

			}


			break;
		default:
			printf("got unhandled event %d \n", debug_event.dwDebugEventCode);
			break;
		}


		//printf("eip now is %p  \n");
		// Resume executing the thread that reported the debugging event. 
		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);

	}




	
	delete(m_modules["server.dll"]); //on le delete puis ecrire destructor dans windows_module

	printf("the process we fuzzed died.. \n");
	kill_process(m_proc);


	/*handle_post_mortem(&debug_event);
	handle_post_mortem(&debug_event);
	DebugActiveProcessStop(GetProcessId(m_proc));
	kill_process(m_proc);*/

	return true; //doit retourner 0 osef vu qu'on save ici si on a detecte un nouveau path
}

/*
mettre bp dans la func qui rewrite l'opcode jeregarde si ça le modifie en lisant la memoire avec reclass ou quoi

//while ( ) on check si l'iteration est finie si elle est finie on retourne si on a detecte des nouveaux path
	{

	}



	Instructions d'utilisation:
		0. cd "C:\Users\b\Desktop\css fuzzing\srcmds"
		1. lancer srcds -game cstrike  
		2. lancer attachable coverage guided fuzzer  "C:\Users\b\source\repos\attachable coverage guided fuzzing css\Release\attachable coverage guided fuzzing css.exe"
		3. Dans srcmds deja appuyer sur Start server tres important de le faire dans cet ordre!
		4. lancer l'injecteur   "C:\Users\b\source\repos\attachable coverage guided fuzzing css\Release\inject.exe"
		5. faire map mysecondmap  et ca va fuzz



*/


/*

got access violation at 78ED0E70 (002F0E70)  in file server.dll

*/