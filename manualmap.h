#pragma once
#include <stdint.h>

class manual_map
{
	int find_hijack_thread(int pid);

	bool execute_shellcode(int pid, void* process_handle, void* shellcode_address);

	bool hijack_call_dllmain(int pid, void* process_handle, uintptr_t func_address, uintptr_t argument);

	//x64 only for now
	bool hijack_loadlib(int pid, void* process_handle, const char* dll);

public:
	bool inject_from_memory(int pid, uint8_t* dll);
	bool inject_from_path(int pid, const char* dll);

	bool hijack_messagebox_test(int pid);
};
