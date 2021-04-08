#pragma once
#include "pch.h"

class PeResource
{
public:
	explicit PeResource(int resourceId, std::wstring resourceName);

	virtual ~PeResource();

	// Delete copy constructor, assignment operator, move constructor, move operator:
	PeResource& operator=(const PeResource&) = delete;
	PeResource(const PeResource&) = delete;
	PeResource(PeResource&&) = delete;
	PeResource& operator=(PeResource&&) = delete;

	LPVOID getResourceData() const;

	void saveResourceToFileSystem(const std::wstring& path) const;

private:
	int m_resourceId;
	std::wstring m_resourceName;
	LPVOID m_resourceData;
	int m_resourceSize;
};