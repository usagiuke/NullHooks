#ifndef _NULL_HOOKS_H_
#define _NULL_HOOKS_H_

#ifdef __cplusplus
extern "C" {
#endif

	DWORD SetHookThread(DWORD threadId);
	DWORD StartHookEngine();
	DWORD StopHookEngine();
	DWORD ProcessHookQueue();
	DWORD ProcessUnhookQueue();
	DWORD AttachHook(PVOID* funcPtr, PVOID hookPtr);
	DWORD DetachHook(PVOID* funcPtr, PVOID hookPtr);

#ifdef __cplusplus
}
#endif

#endif