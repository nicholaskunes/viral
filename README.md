# viral

Viral is a "grey hat" Windows NT takeover kit. The intent of this project is non-malicious but the nature of Viral is a complete takeover of the core OS. You are not to use Viral in any malicious format. Viral is intended for education purposes for everyone (myself especially) in learning how to effectivley program a full virus suite.

## work in progress

Viral ```can NOT be deployed``` straight out of the github repository. I currently am keeping multiple (required) files to myself until they are completed.

## implemented commands

### server -> client

``` /*
			INFO:
				CMD:	setstatus
				ARGS:	int (DEFCON level)
				DESC:	Upgrades/Downgrades Viral's DEFCON level
			*/

			/*
			INFO:
				CMD:	killviral
				ARGS:	[NULL]
				DESC:	Kills Viral. This method will succeed. It is the kill-switch.
			*/