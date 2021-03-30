#pragma once
#include <boost/asio.hpp>
#include <Windows.h>
#include <iostream>
#include <charconv>
#include <string_view>

#ifdef _DEBUG 
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#else
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#endif