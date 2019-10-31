#include "global.h"

DWORD ThreadManager::createThread(char* threadName, std::thread* thread)
{
	HANDLE threadHandle = (*thread).native_handle();
	if (threadHandle) {
		viralThread* vThread = (viralThread*)malloc(sizeof(viralThread));
		vThread->threadHandle = threadHandle;
		vThread->threadActual = thread;
		viralThreads[std::string(threadName)] = vThread;
		return SUCCESS;
	}
	return (internalLastError = CREATE_THREAD_FAILURE);
}

DWORD ThreadManager::killThread(char* threadName)
{
	std::map<std::string, viralThread*>::iterator localIterator;
	localIterator = viralThreads.find(std::string(threadName));
	if (localIterator != viralThreads.end()) {
		viralThread* vThread = localIterator->second;
		if (vThread->threadHandle) {
			if (TerminateThread(vThread->threadHandle, NULL)) {
				CloseHandle(vThread->threadHandle);
				viralThreads.erase(localIterator);
				return SUCCESS;
			}
			else
				return (internalLastError = THREAD_TERMINATION_FAILED);
		}
		else
			return (internalLastError = INVALID_VTHREAD_HANDLE);
	}
	else {
		return (internalLastError = THREAD_NOT_FOUND);
	}
}
