#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <string>


uintptr_t get_module_base(DWORD processId, const CHAR *szModuleName);

uint8_t *create_shared_buffer(std::string buffer_name, size_t size, HANDLE *shared_buffer);

void print_stack_frame(uintptr_t esp); //jsp si cle bon nom jsp si cest stack frame jcrois le obn nom