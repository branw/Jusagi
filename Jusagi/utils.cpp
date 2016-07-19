#include <chrono>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "utils.hpp"

std::vector<process_info> parse_process_list(std::vector<std::string> process_list, int timeout)
{
	std::vector<process_info> processes;

	for (auto process_name : process_list)
	{
		char* p;
		auto pid = strtol(process_name.c_str(), &p, 0);

		// Process specified by name
		if (*p)
		{
			auto end_time = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(timeout);

			auto found = false;
			do
			{
				PROCESSENTRY32 entry;
				entry.dwSize = sizeof(PROCESSENTRY32);

				auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
				if (Process32First(snapshot, &entry))
				{
					while (Process32Next(snapshot, &entry))
					{
						if (_stricmp(entry.szExeFile, process_name.c_str()) == 0)
						{
							pid = entry.th32ProcessID;
							found = true;
							break;
						}
					}
				}

				CloseHandle(snapshot);

				Sleep(100);
			} while (!found && std::chrono::high_resolution_clock::now() < end_time);

			if (pid == 0)
			{
				throw std::exception("Process could not be found by name");
			}
		}

		// Try to open a handle to the process; this does not guarantee the process will still exist
		// when it comes time to inject however, nor that we will have the access rights to do so
		auto process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

		if (process == nullptr)
		{
			throw std::exception("Handle to process could not be opened");
		}

		// Detect the process's architecture
		architecture arch;
		auto is_wow64 = FALSE;
		IsWow64Process(process, &is_wow64);

		if (is_wow64)
		{
			arch = I386;
		}
		else
		{
			_SYSTEM_INFO system_info;
			GetNativeSystemInfo(&system_info);

			switch (system_info.wProcessorArchitecture)
			{
			case PROCESSOR_ARCHITECTURE_INTEL:
				arch = I386;
				break;

			case PROCESSOR_ARCHITECTURE_AMD64:
				arch = AMD64;
				break;

			default:
				throw std::exception("Unsupported process architecture");
			}
		}

		CloseHandle(process);

		processes.push_back({ pid, arch });
	}

	return processes;
}

std::vector<payload_info> parse_payload_list(std::vector<std::string> payload_list)
{
	std::vector<payload_info> payloads;

	for (auto payload_name : payload_list)
	{
		// Expand path into an absolute one
		auto path = new char[_MAX_PATH];
		if (_fullpath(path, payload_name.c_str(), _MAX_PATH) == nullptr)
		{
			throw std::exception("Invalid path");
		}

		// Verify the path is not to a directory
		auto attributes = GetFileAttributes(path);
		if (attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			throw std::exception("Path is not to a file");
		}

		// Check that the file is a Portable Executable
		auto file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		auto file_mapping = CreateFileMapping(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
		auto file_base = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0);
		auto dos_header = static_cast<PIMAGE_DOS_HEADER>(file_base);
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(dos_header) + static_cast<DWORD>(dos_header->e_lfanew));

		if (dos_header->e_magic != 0x5a4d ||
			(!(nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
				!(nt_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)))
		{
			throw std::exception("File is not a Portable Executable");
		}

		architecture arch;
		auto machine = static_cast<architecture>(nt_header->FileHeader.Machine);
		if (machine == IMAGE_FILE_MACHINE_I386)
		{
			arch = I386;
		}
		else if (machine == IMAGE_FILE_MACHINE_AMD64)
		{
			arch = AMD64;
		}
		else
		{
			std::cerr << "Unsupported payload architecture" << std::endl;
			continue;
		}

		UnmapViewOfFile(file_base);
		CloseHandle(file_mapping);
		CloseHandle(file);

		payloads.push_back({ path, arch });
	}

	return payloads;
}
