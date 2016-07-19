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

				VirtualFreeEx(process, page, strlen(file_name), MEM_RELEASE);
				CloseHandle(load_library_thread);

				std::cout << payload.path << " loaded at 0x" << std::hex << *module_handle << " of process ID " << std::dec << target.pid << std::endl;
			}

			CloseHandle(process);
		}
	}
}
