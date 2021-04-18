#include "StringUtils.h"

#include <iomanip>
#include <sstream>

std::string StringUtils::hexValue(std::uint64_t value, int width, char fill, bool upper)
{
	std::stringstream buffer;
	buffer << "0x" << std::hex << std::setw(width) << std::setfill('0') << std::uppercase;

	if (upper)
	{
		buffer << std::uppercase;
	}

	buffer << value;

	return buffer.str();

}