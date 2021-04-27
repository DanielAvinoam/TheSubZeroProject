#pragma once

#ifdef _DEBUG 
#define DEBUG_PRINT(x) do { std::cerr << x << std::endl; } while (0)
#define DEBUG_TEXT(x) x
#else
#define DEBUG_PRINT(x)
#define DEBUG_TEXT(x) ""
#endif