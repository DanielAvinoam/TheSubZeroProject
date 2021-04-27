#include "ProcessEntryIterator.h"
#include "Win32ErrorCodeException.h"
#include "DebugPrint.h"

ProcessEntryIterator::ProcessEntryIterator()
	: m_processesSnapshot(INVALID_HANDLE_VALUE), m_currentProcess{ 0 }, m_noMoreProcessEntries(false)
{
	this->m_processesSnapshot.reset(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (INVALID_HANDLE_VALUE == this->m_processesSnapshot.get())
	{
		throw Win32ErrorCodeException(DEBUG_TEXT("Could not open handle to snapshot"));
	}

	this->m_currentProcess.dwSize = sizeof(PROCESSENTRY32);
	Process32First(this->m_processesSnapshot.get(), &this->m_currentProcess);
}

const PROCESSENTRY32& ProcessEntryIterator::operator*() const
{
	return this->m_currentProcess;
}

ProcessEntryIterator& ProcessEntryIterator::operator++()
{
	this->getNextProcessEntry();
	return *this;
}

bool ProcessEntryIterator::operator!=(EndProcessEntryIterator) const
{
	return !this->m_noMoreProcessEntries;
}

void ProcessEntryIterator::getNextProcessEntry()
{
	if (!Process32Next(this->m_processesSnapshot.get(), &this->m_currentProcess))
	{
		this->m_noMoreProcessEntries = true;
	}
}