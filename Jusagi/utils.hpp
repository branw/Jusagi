#pragma once

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
