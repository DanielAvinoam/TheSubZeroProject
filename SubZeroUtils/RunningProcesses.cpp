#include "RunningProcesses.h"
#include "ProcessEntryIterator.h"

ProcessEntryIterator RunningProcesses::begin() const
{
	return ProcessEntryIterator();
}

EndProcessEntryIterator RunningProcesses::end() const
{
	return EndProcessEntryIterator();
}