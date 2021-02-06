#include "pch.h"
#include "ServiceManager.h"

ServiceManager::ServiceManager(std::wstring srvName, std::wstring srvExePath, std::uint32_t srvType) {

	// Set class members:
	this->serviceName = srvName;
	this->serviceExePath = srvExePath;
	this->serviceType = srvType;

	// Connect to the Service Control Manager
	// and open the Services database:
	this->hSCManager = ::OpenSCManager(
		nullptr,				// local machine
		nullptr,				// local database
		SC_MANAGER_ALL_ACCESS	// access required
	);

	// TODO: Take care in failure.
}

bool ServiceManager::Install() {

	if (!this->hSCManager)
		return false;

	// Create a new a service object:
	this->hService = ::CreateService(
		this->hSCManager,				// handle of service control manager database
		this->serviceName.c_str(),		// address of name of service to start
		this->serviceName.c_str(),		// address of display name
		SERVICE_ALL_ACCESS,				// type of access to service
		//SERVICE_KERNEL_DRIVER,			// type of service
		static_cast<DWORD>(this->serviceType),	// type of service
		SERVICE_DEMAND_START,			// when to start service
		SERVICE_ERROR_NORMAL,			// severity if service fails to start
		this->serviceExePath.c_str(),   // address of name of binary file
		nullptr,						// service does not belong to a group
		nullptr,						// no tag requested
		nullptr,						// no dependency names
		nullptr,						// use LocalSystem account
		nullptr							// no password for service account
	);

	if (this->hService == NULL)
		return false;

	return true;
}

bool ServiceManager::Remove() {

	if (this->hService == NULL)
		return false;

	// Mark the service for deletion from the service control manager database:
	if (::DeleteService(this->hService))
		return true;

	return false;
}

bool ServiceManager::Start() {

	BOOL result;

	if (this->hService == NULL)
		return false;

	// Start the execution of the service (i.e. start the driver):
	result = ::StartService(
		this->hService,	// service handler
		0,				// number of arguments
		nullptr			// pointer to arguments
	);

	if (result)
		return true;

	return false;
}

bool ServiceManager::Stop() {

	BOOL result;
	SERVICE_STATUS  serviceStatus;

	if (this->hService == NULL)
		return false;

	// Request that the service stop:
	result = ::ControlService(
		this->hService,			// service handler
		SERVICE_CONTROL_STOP,	// control codes
		&serviceStatus			// most recent status
	);

	if (result)
		return true;

	return false;
}

ServiceManager::~ServiceManager() {
	try {
		if (this->hSCManager)
			::CloseServiceHandle(this->hSCManager);

		if (this->hService)
			::CloseServiceHandle(this->hService);
	}
	catch (...) {
		// TODO: Log the error
	}
}