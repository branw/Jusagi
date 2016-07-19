#pragma once
#include <string>
#include <vector>

class arg_parser
{
private:
	std::vector<std::string> tokens;

public:
	arg_parser(int& argc, char** argv);
	bool has_arg(const std::string& arg) const;
	const std::string& get_arg_value(const std::string& arg) const;
	std::vector<std::string> get_arg_values(const std::string& arg) const;
};
