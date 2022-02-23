#include "manualmap.h"

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <iostream>

using namespace std;

class c_messagebox
{
public:

	struct data_t
	{
		uintptr_t messagebox_func; //void*, char*, char*, UINT
		char text[255];
		char caption[255];
	};

	//simulated dllmain
	static int __stdcall dllmain(data_t* data, DWORD reason, void* reserved)
	{
		auto msgbox = reinterpret_cast<int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)>(data->messagebox_func);
		msgbox(nullptr, data->text, data->caption, MB_OK);
		return 1;
	}
};

class c_loader
{
public:
	struct data_t
	{
		data_t(uintptr_t _base, uintptr_t _image_base, uintptr_t _entry_point, uintptr_t _base_relocation, uintptr_t _import_directory, uintptr_t _loadlib, uintptr_t _get_proc_address, uintptr_t _messagebox_func)
		{
			base = _base;
			image_base = _image_base;
			entry_point = _entry_point;
			base_relocation = _base_relocation;
			import_directory = _import_directory;
			loadlib = _loadlib;
			get_proc_address = _get_proc_address;
			messagebox_func = _messagebox_func;
		}

		uintptr_t base;
		uintptr_t image_base;
		uintptr_t entry_point;
		uintptr_t base_relocation;
		uintptr_t import_directory;
		uintptr_t loadlib;
		uintptr_t get_proc_address;
		uintptr_t messagebox_func;
	};

	static int __stdcall loader_code(data_t* data, DWORD reason, void* reserved)
	{
		uintptr_t base = data->base;
		uintptr_t delta = base - data->image_base;

		IMAGE_BASE_RELOCATION* base_relocation = (IMAGE_BASE_RELOCATION*)(base + data->base_relocation);
		IMAGE_IMPORT_DESCRIPTOR* import_directory = (IMAGE_IMPORT_DESCRIPTOR*)(base + data->import_directory);

		auto dll_main = reinterpret_cast<int(__stdcall*)(HMODULE, DWORD, void*)>(base + data->entry_point);
		auto loadlib = reinterpret_cast<HMODULE(__stdcall*)(LPCSTR)>(data->loadlib);
		auto get_proc_address = reinterpret_cast<FARPROC(__stdcall*)(HMODULE, LPCSTR)>(data->get_proc_address);
		auto msgbox = reinterpret_cast<int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)>(data->messagebox_func);

		//relocate the image
		while (base_relocation->SizeOfBlock > 0)
		{
			uintptr_t start_address = base + base_relocation->VirtualAddress;

			//relocations in this block
			size_t reloc_count = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

			for (size_t i = 0; i < reloc_count; i++)
			{
				uint16_t reloc_data = *(uint16_t*)(uintptr_t(base_relocation) + sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t) * i);
				uint16_t reloc_type = reloc_data & 0xF000;
				uint16_t reloc_offset = reloc_data & 0x0FFF;

				//this could be wrong
				if (reloc_type == 0xA000)
					*(uintptr_t*)(start_address + reloc_offset) += delta;
			}

			base_relocation = (IMAGE_BASE_RELOCATION*)(uintptr_t(base_relocation) + base_relocation->SizeOfBlock);
		}

		//resolve imports
		while (import_directory->Characteristics)
		{
			//get thunk data
			IMAGE_THUNK_DATA* original_first_thunk = (IMAGE_THUNK_DATA*)(base + import_directory->OriginalFirstThunk);
			IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)(base + import_directory->FirstThunk);

			//load the requested module with loadlibrary :>
			HMODULE import_module = loadlib((LPCSTR)(base + import_directory->Name));

			if (!import_module)
				msgbox(nullptr, (LPCSTR)(base + import_directory->Name), "LIB", MB_OK);

			//bb got dat func in da thunk
			while (original_first_thunk->u1.AddressOfData)
			{
				if (original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					//resolve import func by ordinal (REALLY UNCOMMON)
					LPCSTR func_name = (LPCSTR)(original_first_thunk->u1.Ordinal & 0xFFFF);
					uintptr_t func_addr = (uintptr_t)get_proc_address(import_module, func_name);

					if (!func_addr)
						msgbox(nullptr, (LPCSTR)(base + import_directory->Name), "ORD", MB_OK);

					first_thunk->u1.Function = func_addr;
				}
				else
				{
					//resolve import func by name
					IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(base + original_first_thunk->u1.AddressOfData);
					LPCSTR func_name = (LPCSTR)import_by_name->Name;
					uintptr_t func_addr = (uintptr_t)get_proc_address(import_module, func_name);

					if (!func_addr)
						msgbox(nullptr, (LPCSTR)(base + import_directory->Name), "IBM", MB_OK);

					first_thunk->u1.Function = func_addr;
				}

				original_first_thunk++;
				first_thunk++;
			}

			import_directory++;
		}

		//call entry of module
		dll_main((HMODULE)base, DLL_PROCESS_ATTACH, nullptr);
		return 1;
	}
};

int manual_map::find_hijack_thread(int pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te32{ };
	te32.dwSize = sizeof(THREADENTRY32);

	Thread32First(snapshot, &te32);
	while (Thread32Next(snapshot, &te32))
	{
		if (te32.th32OwnerProcessID == pid)
		{
			CloseHandle(snapshot);
			return te32.th32ThreadID;
		}
	}

	CloseHandle(snapshot);
	return 0;
}

bool manual_map::execute_shellcode(int pid, void* process_handle, void* shellcode_address)
{
	HANDLE process = (HANDLE)process_handle;

	//find thread to hijack
	int thread_index = find_hijack_thread(pid);
	if (!thread_index)
	{
		printf("couldnt find thread to hijack\n");
		return false;
	}

	//open thread
	HANDLE thread = OpenThread(THREAD_ALL_ACCESS | THREAD_GET_CONTEXT, false, thread_index);
	if (!thread)
	{
		printf("couldnt open thread to hijack\n");
		return false;
	}

	//suspend thread
	SuspendThread(thread);

	//get thread context
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(thread, &ctx);

#ifdef _WIN64
	//make room on stack
	ctx.Rsp -= sizeof(uintptr_t);

	//when shellcode is done and calls ret, we jump back to where we left off, so we dont fuck shit up
	WriteProcessMemory(process, (void*)ctx.Rsp, &ctx.Rip, sizeof(ctx.Rip), nullptr);

	//point thread at shellcode
	ctx.Rip = uintptr_t(shellcode_address);
#else
	//make room on stack
	ctx.Esp -= sizeof(uintptr_t);

	//when shellcode is done and calls ret, we jump back to where we left off, so we dont fuck shit up
	WriteProcessMemory(process, (void*)ctx.Esp, &ctx.Eip, sizeof(ctx.Eip), nullptr);

	//point thread at shellcode
	ctx.Eip = uintptr_t(shellcode_address);
#endif

	//set thread context
	SetThreadContext(thread, &ctx);

	//resume thread
	ResumeThread(thread);

	//close thread handle
	CloseHandle(thread);

	return true;
}

bool manual_map::hijack_call_dllmain(int pid, void* process_handle, uintptr_t func_address, uintptr_t argument)
{
	HANDLE process = (HANDLE)process_handle;

	//generate shellcode
#ifdef _WIN64
	uint8_t shellcode[]
	{
		0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,   // push     push registers
		0x48, 0x83, 0xEC, 0x28,                                                         // sub      rsp 0x28
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     // movabs   rcx 0x0000000000000000 
		0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                                       // mov      rdx 0x1
		0x4D, 0x31, 0xC0,                                                               // xor      r8 r8
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     // movabs   rax 0x0000000000000000
		0xFF, 0xD0,                                                                     // call     rax
		0x48, 0x83, 0xC4, 0x28,                                                         // add      rsp 0x28
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D,   // pop      pop registers
		0xC3                                                                            // ret
	};

	*(uintptr_t*)(shellcode + 19) = uintptr_t(argument);
	*(uintptr_t*)(shellcode + 39) = uintptr_t(func_address);
#else
	uint8_t shellcode[]
	{
		0x9C,                           // pushfd   push flags
		0x60,                           // pushad   push registers
		0x68, 0x00, 0x00, 0x00, 0x00,   // push     nullptr (0x0)
		0x68, 0x01, 0x00, 0x00, 0x00,   // push     DLL_PROCESS_ATTACH (0x1)
		0x68, 0x00, 0x00, 0x00, 0x00,   // push     0x00000000
		0xB8, 0x00, 0x00, 0x00, 0x00,   // mov      eax 0x00000000
		0xFF, 0xD0,	                    // call     eax
		0x61,                           // popad    pop registers	
		0x9D,                           // popfd    pop flags
		0xC3                            // ret
	};

	*(uintptr_t*)(shellcode + 13) = uintptr_t(argument);
	*(uintptr_t*)(shellcode + 18) = uintptr_t(func_address);
#endif

	//write shellcode
	void* shellcode_address = VirtualAllocEx(process, nullptr, sizeof(shellcode) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, shellcode_address, shellcode, sizeof(shellcode), nullptr);

	//execute shellcode
	return execute_shellcode(pid, process, shellcode_address);
}

bool manual_map::hijack_loadlib(int pid, void* process_handle, const char* dll)
{
	HANDLE process = (HANDLE)process_handle;

	//write library path
	void* lib_path_address = VirtualAllocEx(process, nullptr, strlen(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(process, lib_path_address, dll, strlen(dll) + 1, nullptr);

	//get loadlib address
	void* loadlib_address = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

#ifdef _WIN64
	//generate shellcode
	uint8_t shellcode[]
	{
		0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push     push registers
		0x48, 0x83, 0xEC, 0x28,                                                       // sub      rsp, 0x28
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rcx, 0x0000000000000000
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rax, 0x0000000000000000
		0xFF, 0xD0,                                                                   // call     rax
		0x48, 0x83, 0xC4, 0x28,                                                       // add      rsp, 0x28
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D, // pop      pop registers
		0xC3                                                                          // ret
	};

	*(uintptr_t*)(shellcode + 19) = uintptr_t(lib_path_address);
	*(uintptr_t*)(shellcode + 29) = uintptr_t(loadlib_address);
#else
	uint8_t shellcode[]
	{
		0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push     push registers
		0x48, 0x83, 0xEC, 0x28,                                                       // sub      rsp, 0x28
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rcx, 0x0000000000000000
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rax, 0x0000000000000000
		0xFF, 0xD0,                                                                   // call     rax
		0x48, 0x83, 0xC4, 0x28,                                                       // add      rsp, 0x28
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D, // pop      pop registers
		0xC3                                                                          // ret
	};
#endif

	//write shellcode
	void* shellcode_address = VirtualAllocEx(process, nullptr, sizeof(shellcode) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, shellcode_address, shellcode, sizeof(shellcode), nullptr);

	//execute shellcode
	return execute_shellcode(pid, process, shellcode_address);
}

bool manual_map::inject_from_memory(int pid, uint8_t* dll)
{
	cout << "[+] Starting injection from memory" << endl;

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
	if (!process)
	{
		cout << "[+] Unable to open process." << endl;
		return false;
	}

	//get headers
	IMAGE_DOS_HEADER* dos_header = (PIMAGE_DOS_HEADER)dll;

	uintptr_t nt_header_addr = dos_header->e_lfanew;
	uintptr_t section_header_addr = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(&dll[nt_header_addr]);
	IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)(&dll[section_header_addr]);

	//get data from headers
	size_t    size_of_image = nt_header->OptionalHeader.SizeOfImage;
	size_t    size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;
	uintptr_t image_base = nt_header->OptionalHeader.ImageBase;
	uintptr_t entry_point = nt_header->OptionalHeader.AddressOfEntryPoint;

	size_t    section_count = nt_header->FileHeader.NumberOfSections;
	uintptr_t reloc_section = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	uintptr_t import_section = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	//allocate data for image
	void* module_address = VirtualAllocEx(process, nullptr, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//write headers
	WriteProcessMemory(process, module_address, dll, size_of_headers, nullptr);

	//write sections
	for (size_t i = 0; i < section_count; i++)
	{
		uintptr_t virtual_address = section_header[i].VirtualAddress + uintptr_t(module_address);
		uintptr_t raw_data_address = section_header[i].PointerToRawData;
		uintptr_t raw_data_size = section_header[i].SizeOfRawData;

		WriteProcessMemory(process, (void*)virtual_address, &dll[raw_data_address], raw_data_size, nullptr);
	}

	//do da loada
	c_loader::data_t loader_data((uintptr_t)module_address,
		image_base,
		entry_point,
		reloc_section,
		import_section,
		(uintptr_t)LoadLibraryA,
		(uintptr_t)GetProcAddress,
		(uintptr_t)MessageBoxA
	);

	void* loader_data_address = VirtualAllocEx(process, nullptr, sizeof(c_loader::data_t), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	void* loader_code_address = VirtualAllocEx(process, nullptr, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(process, loader_data_address, &loader_data, sizeof(c_loader::data_t), nullptr);
	WriteProcessMemory(process, loader_code_address, c_loader::loader_code, 0x4000, nullptr);

	hijack_call_dllmain(pid, process, uintptr_t(loader_code_address), uintptr_t(loader_data_address));

	CloseHandle(process);
	return true;
}

bool manual_map::inject_from_path(int pid, const char* dll)
{
	system("CLS");

	cout << "[+] Injection from path" << endl;
	cout << "[+] Opening %s " << dll << endl;

	//printf( "> injecting from path \n" );
	//printf( "> opening: %s \n", dll );

	HANDLE file_handle = CreateFileA(dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		cout << "[-] Unable to open target Dll." << endl;

		return false;
	}

	DWORD file_size = GetFileSize(file_handle, nullptr);
	uint8_t* buffer = new uint8_t[file_size];

	cout << "[+] Reading %s " << dll << endl;

	if (!ReadFile(file_handle, buffer, file_size, nullptr, nullptr))
	{
		cout << "[-] Unable to read DLL file." << endl;
		CloseHandle(file_handle);
		delete[] buffer;
		return false;
	}
	CloseHandle(file_handle);

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer; //file start 
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("> does not look like a valid DLL! \n");
		cout << "[-] Invalid DLL" << endl;
		delete[] buffer;
		return false;
	}

	cout << "[+] DLL Loaded" << endl;

	inject_from_memory(pid, buffer);

	delete[] buffer;
	return true;
}

bool manual_map::hijack_messagebox_test(int pid)
{
	printf("> messagebox test \n");

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
	if (!process)
	{
		printf("> unable to open process! \n");
		return false;
	}

	c_messagebox::data_t msgbox_data;
	msgbox_data.messagebox_func = uintptr_t(GetProcAddress(GetModuleHandleA("User32.dll"), "MessageBoxA"));
	strncpy_s(msgbox_data.text, 8, "NIGGAS", 8);
	strncpy_s(msgbox_data.caption, 7, "HELLO", 7);

	//write loader data
	void* loader_data_address = VirtualAllocEx(process, nullptr, sizeof(msgbox_data) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, loader_data_address, &msgbox_data, sizeof(msgbox_data), nullptr);

	//write function
	void* dllmain_address = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, dllmain_address, c_messagebox::dllmain, 0x1000, nullptr);

	hijack_call_dllmain(pid, process, uintptr_t(dllmain_address), uintptr_t(loader_data_address));

	CloseHandle(process);

	getchar();

	return true;
}