#include <cstdint>
#include <wtypes.h>

typedef struct _load_library_struct
{
	int status;
	uintptr_t fn_load_library_a;
	uintptr_t module_base;
	char module_name[80];
}load_library_struct;

typedef struct _main_struct
{
	int status;
	uintptr_t fn_dll_main;
	HINSTANCE dll_base;
} main_struct;