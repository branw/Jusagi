#include <Windows.h>
#include <TlHelp32.h>
#include "eject_mode.hpp"
#include <iostream>

namespace eject
{
	void handle(arg_parser &parser)
	{
		if (!parser.has_arg("--process") || !parser.has_arg("--payload"))
		{
			throw std::exception("Both a process and payload must be specified");
		}

		auto process_list = parser.get_arg_values("--process"),
			payload_list = parser.get_arg_values("--payload");

		auto processes = parse_process_list(process_list, 0);
		if (processes.size() == 0)
		{
			throw std::exception("No valid processes specified");
		}

		auto payloads = parse_payload_list(payload_list);
		if (payloads.size() == 0)
		{
			throw std::exception("No valid payloads specified");
		}

		for (auto target : processes)
		{
			auto process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target.pid);

			for (auto payload : payloads) {
				HANDLE module = nullptr;

				MODULEENTRY32 entry;
				entry.dwSize = sizeof(MODULEENTRY32);

				auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, target.pid);
				if (Module32First(snapshot, &entry))
				{
					while (Module32Next(snapshot, &entry))
					{
						if (_stricmp(entry.szExePath, payload.path) == 0)
						{
							module = entry.hModule;
							break;
						}
					}
				}

				if (module == nullptr)
				{
					std::cerr << "Module " << payload.path << " not in process ID " << target.pid << std::endl;
					continue;
				}

				CloseHandle(snapshot);

				// Attempt to unload by mapping binary and executing FreeLibrary in a remote thread
				auto free_library = static_cast<LPVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
				auto free_library_thread = CreateRemoteThread(process, nullptr, NULL, static_cast<LPTHREAD_START_ROUTINE>(free_library), module, 0, nullptr);

				WaitForSingleObject(free_library_thread, INFINITE);

				CloseHandle(free_library_thread);

				std::cout << payload.path << " unloaded from process ID " << std::dec << target.pid << std::endl;
			}

			CloseHandle(process);
		}
	}
}
