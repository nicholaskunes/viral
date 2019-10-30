#pragma once

struct viralThread {
	HANDLE threadHandle;
};

class ThreadManager {
public:
	std::map<std::string, viralThread*> viralThreads;

	DWORD createThread(char* threadName, VOID* threadAddress);
	DWORD killThread(char* threadName);
};