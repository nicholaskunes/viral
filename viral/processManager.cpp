#include "global.h"

DWORD ProcessManager::startSubProcess(char* processName, char* processCommandLineArgs)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	int retvalue = CreateProcessA(processName, (char*)processCommandLineArgs, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	int lastError = GetLastError();

	return 0;
}
