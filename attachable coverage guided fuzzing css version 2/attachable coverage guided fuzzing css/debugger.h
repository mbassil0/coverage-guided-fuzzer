#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <Psapi.h>


#include <vector>
#include <map>
#include <list>
#include <fstream>
#include <string>
#include <chrono>

#include "fuzzer.h"

/*
Debugger used for coverage guided fuzzing
*/

enum bp_type { remove_after_hit = 1, permanent = 2 };

struct breakpoint
{
public:
	breakpoint(uintptr_t address, uint8_t original_byte) { m_address = address; m_original_byte = original_byte; }
	breakpoint() {}

	uintptr_t m_address;
	uint8_t m_original_byte;
	bp_type m_type = remove_after_hit;
};



struct windows_module
{
	/*
	A module like a dll or an exe program that is running in the process we are fuzzing
	*/

	windows_module(std::string _name, uintptr_t base_address) { module_name = _name; base_address = module_base_address; }
	windows_module() {}
	~windows_module() {}
	

	//each module object corresponds to loaded dll/exe on the program
	std::string module_name;
	uintptr_t   module_base_address;
	std::map<std::uintptr_t, breakpoint> breakpoints;

};


class debugger
{
public:
	debugger();
	debugger(HANDLE proc);



	bool run_debugger_in_loop_mode(HANDLE proc, DWORD *exit_code, uint8_t *shared_buffer, size_t shared_buffer_size, std::string buf_name);

	void set_debugger_to_master() { m_is_master_debugger = true; }

private:
	bool write_mem(uintptr_t address, uint8_t *to_write, size_t size_of_data_to_write);
	bool read_mem(uintptr_t address, uint8_t *out_buffer, size_t size_of_data_to_read);

	bool add_breakpoints_from_file(std::string module_name, uintptr_t base_address);
	void add_breakpoint(uintptr_t address, std::string module_name, windows_module *new_module);

	void take_snapshot(DWORD thread_id, uint8_t* shared_buffer);
	void reset_to_snapshot();

	void handle_loop_mode(uint8_t *status_shared_buffer, uint8_t *second_shared_buffer, constantSizeDataManager *data_manager, bool *was_new_bp_hit_during_iteration);

	bool flush_instruction_cache();

	std::string filename_from_module_base(void* base_address);

	DWORD on_load_dll_debug_event(DEBUG_EVENT debug_event);
	bool on_breakpoint_hit(LPDEBUG_EVENT debug_event, uint8_t* shared_buffer, DWORD tid);
	bool on_acces_violation(LPDEBUG_EVENT debug_event, constantSizeDataManager *data_manager, uint8_t *shared_buffer, bool has_fuzzing_started);

	void  on_create_process_debug_eent(LPDEBUG_EVENT debug_event);

	bool remove_breakpoint(uintptr_t address, DWORD tid);


	void print_threads_eip();


	HANDLE m_proc;


	std::map<std::string, windows_module*> m_modules; //jai du mettre un pointeur pour windows_module car sinon ca ne retenait pas les bp que jajoutais pour un module
	std::map<DWORD, HANDLE> m_threads;

	bool is_32bit = true;
	bool m_is_master_debugger = false; //used for multithreading to know which debugger object will measure time and it per sec etc..

	uintptr_t m_engine_base;


	//vu que javais des bugs pendant l'init j'ai decide que cetait mieux dajouter les bp seulement
	//quand ca avait ete bien init
	bool have_bitcoins_been_added = false;
	size_t m_it = 0;
	size_t m_crash_cntr = 0;
	size_t m_number_of_bytes_to_mutate = 20;


	uintptr_t m_snapshot_address_base0 = 0; //the address where we have to take the snapshot but where the base address is 0
	uintptr_t m_snapshot_end_address_base0 = 0; //the address where we will call reset_to_snapshot (a breakpoint will be put at this address by the harness)
	std::string m_snapshot_module;

	std::string m_bps_data_folder_path;  //contains the path to the folder of the breakpoints data (set its value in the function run_debugger_in_loop_mode)
};


extern size_t g_it_ctr;

