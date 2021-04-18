#pragma once
#include "AutoServiceHandle.h"

#include <iostream>

class ServiceManager
{
public:
	explicit ServiceManager(const std::wstring serviceName, const std::wstring filePath, std::uint32_t serviceType);

	virtual ~ServiceManager() = default;

	// Delete copy constructor, assignment operator, move constructor, move operator:
	ServiceManager& operator=(const ServiceManager&) = delete;
	ServiceManager(const ServiceManager&) = delete;
	ServiceManager(ServiceManager&&) = delete;
	ServiceManager& operator=(ServiceManager&&) = delete;

	/* Create a new a service object. */
	void install();

	/* Mark the service for deletion from the service control manager database. */
	void remove() const;

	/* Start the execution of the service. */
	void start() const;

	/* Stop the execution of the service. */
	void stop() const;

	/* Register the service in the SCM and start it. */
	void installAndStart();

	/* Stop the service, remove the service from the SCM. */
	void stopAndRemove() const;

private:
	/* Try open service handle, if succeeded set the service handle member. */
	void tryOpenService();

	std::wstring m_serviceName;
	std::wstring m_serviceBinPath;
	std::uint32_t m_serviceType;
	AutoServiceHandle m_service;
	AutoServiceHandle m_serviceControlManager;
};