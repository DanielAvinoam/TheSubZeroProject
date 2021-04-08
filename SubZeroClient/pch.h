#pragma once
#include <iostream>
#include <Windows.h>

#ifdef _DEBUG 
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#else
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#endif