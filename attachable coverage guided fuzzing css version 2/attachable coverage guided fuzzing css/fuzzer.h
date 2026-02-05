#pragma once
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <vector>

class fuzzer {
public:
	void add_file_to_interesting_inputs();


private:

};







class constantSizeDataManager
{
	/*
	cette classe suppose que les données a mutate (m_data) ont toutes la meme taille
	idée je fais classe generale datamanager (ou plutot fuzzer manager) et constantsizedatamanager herite de ca
	*/
public:
	constantSizeDataManager() { m_data_size = 0; }
	~constantSizeDataManager();

	void reset();
	size_t get_size() { return m_data_size; }


	uint8_t *mutate_data(size_t number_of_bytes_to_mutat, uint8_t *out_buffer);
	void register_input(uint8_t* input);
	void dump_input_to_file(uint8_t* input);
	void dump_input_to_file(uint8_t* input, std::string reason);
	void register_input_from_crash_file(const char *file_name);
	uint8_t *register_and_set_data_size_input_from_file(const char*file_to_open, size_t *original_size);



	std::vector <uint8_t*> m_data;
private:
	//std::vector <uint8_t*> m_data;
	size_t m_data_size = 0; //on suppose que le size est le même pour tous les elements de m_data
};