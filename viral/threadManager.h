#pragma once

struct viralThread {
	HANDLE threadHandle;
	std::thread* threadActual;
};

class ThreadManager {
public:
	std::map<std::string, viralThread*> viralThreads;

	DWORD createThread(char* threadName, std::thread* thread);
	DWORD killThread(char* threadName);
};