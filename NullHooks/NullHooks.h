#ifndef _NULL_HOOKS_H_
#define _NULL_HOOKS_H_

#ifdef __cplusplus
extern "C" {
#endif

	DWORD NTAPI SetHookThread(DWORD threadId);
	DWORD NTAPI StartHookEngine();
	DWORD NTAPI StopHookEngine();
	DWORD NTAPI ProcessHookQueue();
	DWORD NTAPI ProcessUnhookQueue();
	DWORD __fastcall AttachHook(PVOID* funcPtr, PVOID hookPtr);
	DWORD __fastcall DetachHook(PVOID* funcPtr, PVOID hookPtr);

#ifdef __cplusplus
}
#endif

#endif