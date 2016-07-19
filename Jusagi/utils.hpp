#pragma once
#include <vector>

enum architecture
{
	I386,
	AMD64
};

struct process_info
{
	int pid;
	architecture arch;
};

struct payload_info
{
	char *path;
	architecture arch;
};

std::vector<process_info> parse_process_list(std::vector<std::string> process_list, int timeout);
std::vector<payload_info> parse_payload_list(std::vector<std::string> process_list);
