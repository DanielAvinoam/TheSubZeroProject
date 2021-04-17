#pragma once

#include <string>

class StringUtils final
{
public:
	static std::string hexValue(std::uint64_t value, int width = 16, char fill = '0', bool upper = true);
};