#include "fuzzer.h"
#include <string>
#include <Windows.h>





/* CRC-32C (iSCSI) polynomial in reversed bit order. */
#define POLY 0x82f63b78

/* CRC-32 (Ethernet, ZIP, etc.) polynomial in reversed bit order. */
/* #define POLY 0xedb88320 */
/* initial value of crc should be 0 todo change this function.. */
uint32_t crc32c(uint32_t crc, const unsigned char *buf, size_t len)
{
	int k;

	crc = ~crc;
	while (len--) {
		crc ^= *buf++;
		for (k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
	}
	return ~crc;
}

void constantSizeDataManager::reset()
{
	for (size_t i = 0; i < m_data.size(); i++)
	{
		free(m_data[i]);
	}

	m_data.clear();
}

uint8_t *constantSizeDataManager::mutate_data(size_t number_of_bytes_to_mutat, uint8_t *out_buffer)
{
	/*
		returns the mutated data
		pas oublier de register au moins un input (qui peut valoir 0) sinon ça va crash si m_data.size() vaut 0

		NOTE m_data ne peut pas etre vide ou ca va crash
	*/
	size_t rand_idx = rand() % m_data.size();



	memcpy(out_buffer, m_data[rand_idx], m_data_size); //on choisit une donnée a mutate parmis celle qu'on a enregistrée (càd celle qui nous donnes des path interessant pour fuzz)

	/*for (size_t i = 0; i < number_of_bytes_to_mutat; i++)
	{
		size_t random_index = rand() % m_data_size;
		out_buffer[random_index] = rand() % 256;

	}*/
	
	static int i = 0;
	
	
	i += 1;
	if (i == 8)
		i += 205;

	printf("%d \n", i);
	i = 322;

	out_buffer[i%400] = 420;
	return out_buffer;
}

constantSizeDataManager::~constantSizeDataManager()
{
	for (size_t i = 0; i < m_data.size(); i++)
	{
		free(m_data[i]);
	}
}

void constantSizeDataManager::register_input(uint8_t* input)
{
	

	uint8_t* tmp = (uint8_t*)malloc(m_data_size);
	printf("registr input %p   %p  size: %d  \n", tmp, input, m_data_size);
	
	memcpy_s(tmp, m_data_size, input, m_data_size);
	m_data.push_back(tmp);
}


void constantSizeDataManager::dump_input_to_file(uint8_t* input)
{
	std::ofstream file;
	std::string file_name = "crash" + std::to_string(crc32c(0, input, m_data_size)); //todo add date ?
	file.open(file_name + ".txt", std::ios::binary | std::ios::out);


	file.write((char*)&m_data_size, 4);
	file.write((char*)input, m_data_size);
	file.close();
}

void constantSizeDataManager::dump_input_to_file(uint8_t* input, std::string file_name)
{
	std::ofstream file;
	//std::string file_name = std::to_string(crc32c(0, input, m_data_size)) + reason ; //todo add date ?
	file.open(file_name + ".txt", std::ios::binary | std::ios::out);


	file.write((char*)&m_data_size, 4);
	file.write((char*)input, m_data_size);
	file.close();

}

void constantSizeDataManager::register_input_from_crash_file(const char *file_name)
{
	/*
	todo handle 64bit
	ajoute un file qui a fait crash le target a notre liste d'input
	*/
	std::ifstream  f(file_name, std::ios::binary);
	size_t data_size;

	if (f.fail())
	{
		printf("register_input_from_file failed to open the file \n");
		return;
	}

	f.read((char*)&data_size, 4);
	if (data_size != m_data_size && m_data_size != 0)
	{
		printf("register_input_from_file data_size from the file doesn't have the expected value \n");
		return;
	}

	m_data_size = data_size;
	uint8_t *bytes = (uint8_t*)malloc(m_data_size);
	f.read((char*)bytes, m_data_size);
	m_data.push_back(bytes);
	f.close();
}

uint8_t *constantSizeDataManager::register_and_set_data_size_input_from_file(const char*file_to_open, size_t *original_size)
{
	/*
	todo rewrite it in c++ style..
	*/

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

	m_data.push_back(map_input);
	
	if (m_data_size != size)
		printf("register_input_from_file the size already registered is different original size: %d  new size: %d \n", m_data_size, size);

	*original_size = size;
	m_data_size = size;
	return map_input;

}
