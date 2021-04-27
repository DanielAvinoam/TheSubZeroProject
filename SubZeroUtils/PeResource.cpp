#include "PeResource.h"
#include "Win32ErrorCodeException.h"
#include "AutoHandle.h"
#include "DebugPrint.h"

PeResource::PeResource(int resourceId, std::wstring resourceName)
	: m_resourceId(resourceId), m_resourceName(resourceName)
{
	// Search for the resource in the current module
	const HRSRC resource = FindResource(nullptr, MAKEINTRESOURCE(this->m_resourceId), this->m_resourceName.c_str());
	if (nullptr == resource)
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Could not find resource with ID: " + this->m_resourceId));
	}

	// Search for the resource in the current module
	this->m_resourceSize = SizeofResource(nullptr, resource);
	if (0 >= this->m_resourceSize)
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Invalid resource size"));
	}

	// Load the resource from the current module
	const HGLOBAL loadedResource = LoadResource(nullptr, resource);
	if (nullptr == loadedResource)
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Could not load the resource"));
	}

	this->m_resourceData = LockResource(loadedResource);
	if (nullptr == this->m_resourceData)
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Could not retrieve pointer to the resource"));
	}
}

PeResource::~PeResource()
{
	// According to MSDN no need to release the lock or the resource.
}

LPVOID PeResource::getResourceData() const
{
	return this->m_resourceData;
}

void PeResource::saveResourceToFileSystem(const std::wstring& path) const
{
	if (nullptr == this->m_resourceData)
	{
		throw std::runtime_error(DEBUG_TEXT("Invalid resource data"));
	}

	const AutoHandle file(CreateFile(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL, nullptr));
	if (INVALID_HANDLE_VALUE == file.get())
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Could not create target file"));
	}

	DWORD writeBytes;
	if (!WriteFile(file.get(), this->m_resourceData, this->m_resourceSize, &writeBytes, nullptr))
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Could not write resource data to target file"));
	}
}