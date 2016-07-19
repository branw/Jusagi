#pragma once
#include "arg_parse.hpp"
#include "utils.hpp"

namespace inject
{
	void handle(arg_parser &parser);

	std::vector<process_info> parse_process_list(std::vector<std::string> process_list, int timeout);
	std::vector<payload_info> parse_payload_list(std::vector<std::string> process_list);
}
