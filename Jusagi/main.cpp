#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include "inject_mode.hpp"
#include "eject_mode.hpp"
#include "arg_parse.hpp"

int main(int argc, char *argv[])
{
	arg_parser parser(argc, argv);

	if (argc == 1 || parser.has_arg("--help"))
	{
		std::cout 
			<< "A Windows command-line tool for loading binaries into processes." << std::endl << std::endl
			<< "Injecting a module:" << std::endl
			<< "Jusagi inject --process <identifier> --payload <path> [--delay <ms>] [--timeout <ms>]" << std::endl
			<< "  --process <identifier>    Specify a process to inject into (multiple allowed)" << std::endl
			<< "            (Process ID or file name)" << std::endl
			<< "  --payload <path>          Specify a payload to inject (multiple allowed)" << std::endl
			<< "  --delay <ms>              Time to wait before injecting, in milliseconds" << std::endl
			<< "  --timeout <ms>            Time to wait for a process to be found, in milliseconds" << std::endl << std::endl
			<< "Ejecting/unloading a module:" << std::endl
			<< "Jusagi eject --process <identifier> --payload <path>" << std::endl
			<< "  --process <identifier>    Specify a process to inject into (multiple allowed)" << std::endl
			<< "            (Process ID or file name)" << std::endl
			<< "  --payload <path>          Specify a payload to inject (multiple allowed)" << std::endl << std::endl
			<< "Options:" << std::endl
			<< "  --help                    Display this help manual" << std::endl
			<< "  --version                 Display the version" << std::endl;
		return EXIT_SUCCESS;
	}

	if (parser.has_arg("--version"))
	{
		std::cout << "Jusagi 0.1.0" << std::endl;
		return EXIT_SUCCESS;
	}

	auto mode = std::string(argv[1]);

	try {
		if (mode == "inject")
		{
			inject::handle(parser);
		}
		else if (mode == "eject")
		{
			eject::handle(parser);
		}
		else
		{
			throw std::exception("Invalid mode");
		}
	}
	catch (std::exception &e)
	{
		std::cerr << "Fatal error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
