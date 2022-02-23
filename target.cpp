#include "Target.h"

#include <Windows.h>
#include <tlhelp32.h>

std::vector<TargetProcess> Target::potential_targets = {
	{ "Fortnite", "FortniteClient-Win64-Shipping.exe", "nigger.dll", X64, false },
};

int Target::is_valid_target(std::string target_name) {
	Architecture_t architecture = (Architecture_t)(sizeof(void*) == 8);

	for (size_t i = 0; i < potential_targets.size(); i++) {
		TargetProcess& potential_target = potential_targets.at(i);
		if (potential_target.architecture == architecture && potential_target.process_name.compare(target_name) == 0) {
			return (int)i;
		}
	}

	return -1;
}

int Target::find_target(TargetProcess* target) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return -1;

	PROCESSENTRY32 entry = { NULL };
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &entry)) {
		CloseHandle(hSnapshot);
		return -1;
	}

	do {
		int potential_target_id = is_valid_target(entry.szExeFile);
		if (potential_target_id != -1) {
			CloseHandle(hSnapshot);
			*target = potential_targets.at(potential_target_id);
			return entry.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &entry));

	CloseHandle(hSnapshot);
	return -1;
}