#pragma once
#include "pch.h"

class Win32ErrorCodeException : public std::runtime_error
{
public:
	explicit Win32ErrorCodeException(const std::string& errorMessage);

	virtual ~Win32ErrorCodeException() = default;

	const char* what() const override;

	// Delete copy constructor & assignment operator
	// @note std::exception using the move constructor when throwing exception.
	Win32ErrorCodeException(const Win32ErrorCodeException&) = delete;
	Win32ErrorCodeException& operator=(const Win32ErrorCodeException&) = delete;
	Win32ErrorCodeException(Win32ErrorCodeException&&) = default;
	Win32ErrorCodeException& operator=(Win32ErrorCodeException&&) = default;

	/* Get Windows last error code. */
	DWORD getErrorCode() const;

	/* Get Windows message corresponding to the last error that occurred. */
	std::string getWinErrorMessage() const;

protected:
	static std::string getLastErrorMessage();

	DWORD m_errorCode;
	std::string m_winErrorMessage;
	std::string m_errorMessage;
};