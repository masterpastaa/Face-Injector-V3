#include "define/stdafx.h"
#include "api/xor.h"
#include "api/api.h"
#include "driver/driver.h"
#include "inject.h"
#include "api/drvutils.h"
#include "manualmap.h"
#include "target.h"
#include "add.h"

/*
    
    This is a modified version of Face Injector V2, i added some things that can be "usefull" i guess.
	I know this should be more a Face Injection v2.5 or something like that instead of V3.
	Contact me on discord if you need help, masterpasta#0001.

*/

std::string GetDLLPath(std::string dllName)
{
	std::string dllPath;
	char tempPath[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), tempPath, (sizeof(tempPath)));
	PathRemoveFileSpec(tempPath);
	std::string path(tempPath);
	path += "\\" + dllName;
	return path;
}

void Inject_lol(int pID, std::string dllPath, bool can_manual_map) {
	bool IsInjected = false;

	if (can_manual_map) 
	{
		/* Code cleared because it's pretty useless right now, but you can do something with it, if you for example add another injection method */
	}

	manual_map mapper;
	IsInjected = mapper.inject_from_path(pID, dllPath.c_str());

	if (!IsInjected)
	{
		cout << xor_a("[-] Injection failed") << endl;
	}
}

int main()
{
	start_driver();
	cout << endl;

	TargetProcess target;
	string dllPath = GetDLLPath(target.dll_name);
	int pid = Target::find_target(&target);

	/* Asking and reading reply*/
	std::cout << xor_a("[>] Class: ") << endl;
	std::cin >> test;

	system(xor_a("CLS"));

	std::cout << xor_a("[1] ManualMap") << xor_a("\n") << xor_a("[2] Default Injection (FACE INJECTION)") << std::endl;
	std::cin >> reply;

	/* if reply = 1 (manualmap) */
	if (reply == xor_a("1"))
	{
		if (pid != -1)
		{
			printf(xor_a("[+] Target: %s \n"), target.display_name.c_str());
			printf(xor_a("[+] Process: %s \n"), target.process_name.c_str());
			printf(xor_a("[+] Process ID: %i \n"), pid);
			printf(xor_a("[+] DLL: %s \n"), target.dll_name.c_str());
			printf(xor_a("[+] DLL Path: %s \n"), dllPath.c_str());

			Inject_lol(pid, dllPath, target.manual_map);

			Sleep(-1);
		}
		else 
		{
			std::cout << xor_a("[+] Couldn't find any valid target process.\n");
		}

	}

	/* if reply = 2 (default one) */
	else if (reply == xor_a("2"))
	{
		inject(test.c_str(), xor_w(L"test.dll"));
		Sleep(-1);
	}

	/* if user entered an invalid selection, like '3 or 4' or anything else than 1 & 2 */
	else
	{
		std::cout << xor_a("[-] Invalid Selection.") << std::endl;
		Sleep(-1);
	}

	/* Calling injection in specified Class name and default dll (can be changed) */
	

	cout << endl;
	Sleep(-1);
}


/*
    
    Added a class finder, directly ask you the class name of the process that you want to inject in.

*/