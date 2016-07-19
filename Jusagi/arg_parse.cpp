#include "arg_parse.hpp"

arg_parser::arg_parser(int& argc, char** argv)
{
	for (auto i = 1; i < argc; ++i)
		this->tokens.push_back(std::string(argv[i]));
}

bool arg_parser::has_arg(const std::string& arg) const
{
	return std::find(this->tokens.begin(), this->tokens.end(), arg) != this->tokens.end();
}

const std::string& arg_parser::get_arg_value(const std::string& arg) const
{
	auto itr = std::find(this->tokens.begin(), this->tokens.end(), arg);
	if (itr != this->tokens.end() && ++itr != this->tokens.end())
	{
		return *itr;
	}
	return "";
}

std::vector<std::string> arg_parser::get_arg_values(const std::string& arg) const
{
	std::vector<std::string> options;
	auto i = this->tokens.begin(), end = this->tokens.end();
	while (true)
	{
		i = std::find(i, this->tokens.end(), arg);
		if (i == this->tokens.end()) break;
		i = std::next(i);
		options.push_back(*i);
	}
	return options;
}
