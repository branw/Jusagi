#include <chrono>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "inject_mode.hpp"

namespace inject
{
	void handle(arg_parser& parser)
	{
		if (!parser.has_arg("--process") || !parser.has_arg("--payload"))
		{
			throw std::exception("Both a process and payload must be specified");
		}

		auto process_list = parser.get_arg_values("--process"),
			payload_list = parser.get_arg_values("--payload");

		auto timeout = 0;
		if (parser.has_arg("--timeout"))
		{
			try
			{
				timeout = std::stoi(parser.get_arg_value("--timeout"));
			}
			catch (std::exception& e)
			{
				throw std::exception("Invalid timeout value");
			}
		}

		auto delay = 0;
		if (parser.has_arg("--delay"))
		{
			try
			{
				timeout = std::stoi(parser.get_arg_value("--delay"));
			}
			catch (std::exception& e)
			{
				throw std::exception("Invalid delay value");
			}
		}

		auto processes = parse_process_list(process_list, timeout);
		if (processes.size() == 0)
		{
			throw std::exception("No valid processes specified");
		}

		auto payloads = parse_payload_list(payload_list);
		if (payloads.size() == 0)
		{
			throw std::exception("No valid payloads specified");
		}

		if (delay > 0) {
			auto end_time = std::chrono::high_resolution_clock::now() + std::chrono::milliseconds(delay);

			while (std::chrono::high_resolution_clock::now() < end_time) Sleep(delay/10);
		}

		for (auto target : processes)
		{
			auto process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target.pid);

			for (auto payload : payloads)
			{
				if (target.arch != payload.arch)
				{
					std::cerr << "Payload architecture does not match process architecture" << std::endl;
					continue;
				}

				// Attempt to inject by mapping binary and executing LoadLibrary in a remote thread
				auto file_name = _fullpath(nullptr, payload.path, MAX_PATH);

				auto load_library = static_cast<LPVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

				auto page = VirtualAllocEx(process, nullptr, strlen(file_name), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				WriteProcessMemory(process, page, file_name, strlen(file_name), nullptr);

				auto load_library_thread = CreateRemoteThread(process, nullptr, NULL, static_cast<LPTHREAD_START_ROUTINE>(load_library), page, 0, nullptr);

				WaitForSingleObject(load_library_thread, INFINITE);

				auto module_handle = new DWORD;
				GetExitCodeThread(load_library_thread, module_handle);

				std::cout << payload.path << " loaded at 0x" << std::hex << *module_handle << " of process ID " << std::dec << target.pid << std::endl;

				VirtualFreeEx(process, page, strlen(file_name), MEM_RELEASE);
				CloseHandle(load_library_thread);
			}

			CloseHandle(process);
		}
	}

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
				}
				while (!found && std::chrono::high_resolution_clock::now() < end_time);

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

			processes.push_back({pid, arch});
		}

		return processes;
	}

	std::vector<payload_info> parse_payload_list(std::vector<std::string> payload_list)
	{
		std::vector<payload_info> payloads;

		for (auto payload_name : payload_list)
		{
			// Expand path into an absolute one
			auto path = new char[_MAX_PATH ];
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

			payloads.push_back({path, arch});
		}

		return payloads;
	}
}
