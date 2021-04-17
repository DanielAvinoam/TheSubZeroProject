#include "pch.h"
#include "Win32ErrorCodeException.h"

Win32ErrorCodeException::Win32ErrorCodeException(const std::string& errorMessage)
	: std::runtime_error(errorMessage), m_errorCode(0)
{
	this->m_errorCode = GetLastError();
	this->m_winErrorMessage = getLastErrorMessage();

	std::stringstream messageStream;
	messageStream << "[-] ";
	messageStream << std::runtime_error::what();
	messageStream << "\n[-] Windows last error code: 0x";
	messageStream << std::hex << this->m_errorCode;
	messageStream << "\n[-] Windows error message: ";
	messageStream << this->m_winErrorMessage;
	this->m_errorMessage = messageStream.str();
}

const char* Win32ErrorCodeException::what() const
{
	return this->m_errorMessage.c_str();
}


DWORD Win32ErrorCodeException::getErrorCode() const
{
	return this->m_errorCode;
}

std::string Win32ErrorCodeException::getWinErrorMessage() const
{
	return this->m_winErrorMessage;
}

std::string Win32ErrorCodeException::getLastErrorMessage()
{
	const DWORD errorCode = GetLastError();
	if (0 == errorCode)
	{
		return "";
	}

	const int MESSAGE_SIZE = 512;
	std::vector<WCHAR> message(MESSAGE_SIZE);

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorCode,
		0, &message[0], MESSAGE_SIZE, nullptr);

	return std::string(CW2A(message.data()));
}