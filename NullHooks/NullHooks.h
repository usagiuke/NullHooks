
#ifdef __cplusplus
extern "C" {
#endif

	DWORD NTAPI SetHookThread(DWORD threadId);
	DWORD NTAPI StartHookEngine();
	DWORD NTAPI StopHookEngine();
	DWORD NTAPI ProcessHookQueue();
	DWORD NTAPI ProcessUnhookQueue();
	DWORD NTAPI AttachHook(PVOID* funcPtr, PVOID hookPtr);
	DWORD NTAPI DetachHook(PVOID* funcPtr, PVOID hookPtr);

#ifdef __cplusplus
}
#endif