#pragma once
#include <Windows.h>
#include <iostream>

#ifdef _DEBUG 
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#else
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#endif