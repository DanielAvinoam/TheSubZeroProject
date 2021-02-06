#pragma once
#include "pch.h"

class ServiceManager
{
private:
	SC_HANDLE hService;
	SC_HANDLE hSCManager;
	std::wstring serviceName;
	std::wstring serviceExePath;
	std::uint32_t serviceType;

public:
	ServiceManager(std::wstring srvName, std::wstring srvExePath, std::uint32_t srvType);
	~ServiceManager();
	bool Install();
	bool Remove();
	bool Start();
	bool Stop();
};

