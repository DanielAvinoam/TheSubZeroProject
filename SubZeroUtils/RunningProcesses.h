#pragma once
#include "ProcessEntryIterator.h"

class RunningProcesses
{
public:
	RunningProcesses() = default;

	virtual ~RunningProcesses() = default;

	// delete copy ctor, move ctor, assignment
	RunningProcesses(const RunningProcesses&) = delete;
	RunningProcesses& operator=(const RunningProcesses&) = delete;
	RunningProcesses(RunningProcesses&&) = delete;
	RunningProcesses& operator=(RunningProcesses&&) = delete;

	/*
	 * Start iterator instance.
	 * @return Iterator for processes information.
	 */
	ProcessEntryIterator begin() const;

	/*
	 * Indicating the end of the iteration.
	 * @note Different types between begin() and end() available from C++17. https://stackoverflow.com/a/62716532
	 * @return Dummy class.
	 */
	EndProcessEntryIterator end() const;
};
