#pragma once
#include <string>
#include <vector>

enum Architecture_t {
	X86,
	X64
};

struct TargetProcess {
	std::string display_name;
	std::string process_name;
	std::string dll_name;
	Architecture_t architecture;
	bool manual_map;
	int process_id;
};

class Target {
	static std::vector<TargetProcess> potential_targets;
	static int is_valid_target(std::string target_name);
public:
	static int find_target(TargetProcess* target);
};