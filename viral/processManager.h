#pragma once

class ProcessManager {
public:
	std::vector<int> childProcesses;

	DWORD startSubProcess(char* processName, char* processCommandLineArgs);
};