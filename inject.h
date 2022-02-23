#include <Windows.h>
#include "inject/utils.h"
#include "api/xor.h"
#include "define/stdafx.h"
#include "driver/driver.h"
#include "inject/injection_features.h"


void inject(LPCSTR window_class_name, LPCWSTR dll_path)
{
	/* Get Dll Image */
	PVOID dll_image = get_dll_by_file(dll_path);
	if (!dll_image)
	{
		printf(xor_a("[-] Invalid DLL\n"));
	}


	/* Parse NT Headers */
	PIMAGE_NT_HEADERS dll_nt_head = RtlImageNtHeader(dll_image);
	if (!dll_nt_head)
	{
		printf(xor_a("[-] Invalid PE Header.\n"));
	}

	/* useless informations lol */
	DWORD thread_id;
	DWORD process_id = get_process_id_and_thread_id_by_window_class(window_class_name, &thread_id);

	cout << xor_a("[+] Process ID: 0x") << hex << process_id << endl;
	cout << xor_a("[+] Thread  ID: 0x") << hex << thread_id << endl;

	if (process_id != 0 && thread_id != 0)
	{
		// attach target process
		driver().attach_process(process_id);

		PVOID allocate_base = driver().alloc_memory_ex(dll_nt_head->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
		cout << xor_a("[+] Allocated Base: 0x") << hex << allocate_base << endl;

		// fix reloc
		if (!relocate_image(allocate_base, dll_image, dll_nt_head))
		{
			driver().free_memory_ex(allocate_base);
			printf(xor_a("[-] Relocation failed.\n"));
		}

		printf(xor_a("[+] Successfully relocated image.\n"));

		// fix iat
		if (!resolve_import(thread_id, dll_image, dll_nt_head))
		{
			driver().free_memory_ex(allocate_base);
			printf(xor_a("[+] Imports failed.\n"));
		}

		printf(xor_a("[+] Successfully resolved imports.\n"));

		// write dll section's
		write_sections(allocate_base, dll_image, dll_nt_head);

		printf(xor_a("[+] Successfully wrote sections\n"));

		// call dll main
		call_dll_main(thread_id, allocate_base, dll_nt_head, false);

		printf(xor_a("[+] Called dllmain.\n"));

		// cleanup
		erase_discardable_sect(allocate_base, dll_nt_head);
		VirtualFree(dll_image, 0, MEM_RELEASE);

		printf(xor_a("[+] Injected.\n"));
		cout << endl;
	}
	else
	{
		printf(xor_a("[-] Process not found.\n"));
	}
}