#pragma once
#include "AutoHandle.h"

#include <TlHelp32.h>
#include <Windows.h>

/*
 * Used as an indication the iterator have no more iterations.
 */
class EndProcessEntryIterator {};

class ProcessEntryIterator
{
public:
	ProcessEntryIterator();

	// delete copy ctor, move ctor, assignment
	ProcessEntryIterator(const ProcessEntryIterator&) = delete;
	ProcessEntryIterator& operator=(const ProcessEntryIterator&) = delete;
	ProcessEntryIterator(ProcessEntryIterator&&) = delete;
	ProcessEntryIterator& operator=(ProcessEntryIterator&&) = delete;

	virtual ~ProcessEntryIterator() = default;

	const PROCESSENTRY32& operator*() const;

	ProcessEntryIterator& operator++();

	bool operator!=(EndProcessEntryIterator) const;

private:
	/* Verify if there are more running processes to query, if not setting flag. */
	void getNextProcessEntry();

	AutoHandle m_processesSnapshot;
	PROCESSENTRY32 m_currentProcess;
	bool m_noMoreProcessEntries;
};