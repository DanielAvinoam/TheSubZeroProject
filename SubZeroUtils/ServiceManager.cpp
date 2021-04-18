#include "ServiceManager.h"
#include "Win32ErrorCodeException.h"

#include <stdexcept>

ServiceManager::ServiceManager(const std::wstring serviceName, const std::wstring filePath, std::uint32_t serviceType)
	: m_serviceName(serviceName), m_serviceBinPath(filePath), m_serviceType(serviceType), m_service(nullptr),
	m_serviceControlManager(nullptr)
{
	this->m_serviceControlManager.reset(OpenSCManager(
		nullptr,				// local machine
		nullptr,				// local database
		SC_MANAGER_ALL_ACCESS	// access required
	));

	if (nullptr == this->m_serviceControlManager.get())
	{
		throw Win32ErrorCodeException("Could not open handle to the SCManager");
	}

	this->tryOpenService();
}

void ServiceManager::install()
{
	if (nullptr == this->m_serviceControlManager.get())
	{
		throw std::runtime_error("Invalid SCManager, could not install the service");
	}

	this->m_service.reset(CreateService(
		this->m_serviceControlManager.get(), // handle of service control manager database
		this->m_serviceName.c_str(),	// address of name of service to start
		this->m_serviceName.c_str(),	// address of display name
		SERVICE_ALL_ACCESS,				// type of access to service
		this->m_serviceType,			// type of service
		SERVICE_DEMAND_START,			// when to start service
		SERVICE_ERROR_NORMAL,			// severity if service fails to start
		this->m_serviceBinPath.c_str(), // address of name of binary file
		nullptr,						// service does not belong to a group
		nullptr,						// no tag requested
		nullptr,						// no dependency names
		nullptr,						// use LocalSystem account
		nullptr							// no password for service account
	));

	if (nullptr == this->m_service.get())
	{
		throw Win32ErrorCodeException("Could not create the service");
	}
}

void ServiceManager::remove() const
{
	if (nullptr == this->m_service.get())
	{
		throw std::runtime_error("Invalid service handle, could not remove the service");
	}

	if (!DeleteService(this->m_service.get()))
	{
		throw Win32ErrorCodeException("Could not remove the service");
	}
}

void ServiceManager::start() const
{
	if (nullptr == this->m_service.get())
	{
		throw std::runtime_error("Invalid service handle, could not start service");
	}

	if (!StartService(this->m_service.get(),
		0,				// number of arguments
		nullptr			// pointer to arguments
	))
	{
		throw Win32ErrorCodeException("Could not start the service");
	}
}

void ServiceManager::stop() const
{
	if (nullptr == this->m_service.get())
	{
		throw std::runtime_error("Invalid service handle, could not stop service");
	}

	SERVICE_STATUS  serviceStatus;
	if (!ControlService(this->m_service.get(),
		SERVICE_CONTROL_STOP,	// control codes
		&serviceStatus			// most recent status
	))
	{
		throw Win32ErrorCodeException("Could not stop the service");
	}
}

void ServiceManager::installAndStart()
{
	this->install();
	this->start();
}

void ServiceManager::stopAndRemove() const
{
	this->stop();
	this->remove();
}

void ServiceManager::tryOpenService()
{
	const SC_HANDLE service = OpenService(this->m_serviceControlManager.get(), this->m_serviceName.c_str(),
		SC_MANAGER_ALL_ACCESS);

	if (nullptr != service)
	{
		this->m_service.reset(service);
	}
}