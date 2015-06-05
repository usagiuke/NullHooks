#include "stdafx.h"
#include "insn.h"
#include <stdint.h>

static const int is64Bit = sizeof(void*) == 8;
static const int jmpOpSize = sizeof(void*) == 8 ? 14 : 5;

#define InitHookChunk(o,a,b,c,d,e,f) o->_functionPointer = a;\
	o->_trampolinePointer = b;\
o->_hookPointer = c;\
o->_allignmentBytes = d;\
o->_jmpDistance = e;\
o->_trampolineAllocSize = f;\
o->vft_hook = 0

struct HookChunk
{
	int vft_hook;
	PVOID _functionPointer;
	PVOID _trampolinePointer;
	PVOID _hookPointer;
	DWORD _allignmentBytes;
	int _jmpDistance;
	SIZE_T _trampolineAllocSize;
};

DWORD HookThread;
struct HookChunk** HookQueueArray = NULL;
struct HookChunk** UnhookQueueArray = NULL;
DWORD HookCount = 0u;
DWORD UnhookCount = 0u;
BOOL engineRunning = FALSE;

static int CalculateJmp(int dest, int src)
{
	int jmpDest = dest;
	int jmpSrc = src + 5;
	return jmpDest - jmpSrc;
}

static BOOL SuspendProcess()
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return(FALSE);
	}

	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(obj, 0, 0, 0, 0);
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)GetCurrentProcessId();
	do
	{
		if (te32.th32ThreadID != HookThread)
		{
			HANDLE hThread;
			cid.UniqueThread = (HANDLE)te32.th32ThreadID;
			NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, &obj, &cid);
			NtSuspendThread(hThread, NULL);
			NtClose(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

static BOOL ResumeProcess()
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return(FALSE);
	}

	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(obj, 0, 0, 0, 0);
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)GetCurrentProcessId();
	do
	{
		if (te32.th32ThreadID != HookThread)
		{
			HANDLE hThread;
			cid.UniqueThread = (HANDLE)te32.th32ThreadID;
			NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, &obj, &cid);
			NtResumeThread(hThread, NULL);
			NtClose(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

DWORD SetHookThread(DWORD threadId)
{
	HookThread = threadId;
	return 0;
}

DWORD ProcessHookQueue()
{

	SuspendProcess();

	for (DWORD i = 0u; i < HookCount; i++)
	{
		struct HookChunk* hook = HookQueueArray[i];
		if (hook->vft_hook) {
			PVOID* vftableLoc = *(PVOID**)hook->_functionPointer;
			PVOID pagePtr = (PVOID)vftableLoc;
			SIZE_T pointerSize = sizeof(PVOID);
			ULONG oldProtect;
			NtProtectVirtualMemory(GetCurrentProcess(), &pagePtr, &pointerSize, PAGE_EXECUTE_READWRITE, &oldProtect);
			PVOID realFunction = vftableLoc[0];
			vftableLoc[0] = hook->_hookPointer;
			((PVOID*)hook->_functionPointer)[0] = realFunction;
			NtProtectVirtualMemory(GetCurrentProcess(), &pagePtr, &pointerSize, oldProtect, &oldProtect);
			free(hook);
			continue;
		}
		PUCHAR funcBytes = (PUCHAR)hook->_functionPointer;
		PVOID pageptr = funcBytes;
		SIZE_T thunkSize = hook->_allignmentBytes + jmpOpSize;
		ULONG oldProtect;
		NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pageptr, &thunkSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		if (!is64Bit) {
			funcBytes[0] = 0xE9;
			((int*)&funcBytes[1])[0] = hook->_jmpDistance;
		}
		else {
#pragma pack(push, 1)
			struct {
				uint8_t jmpFF;
				uint8_t jmp25;
				uint32_t zero;
				void* dest;
			} jmp64 = { 0xFF, 0x25, 0x00000000, hook->_hookPointer };
			memcpy_s(&funcBytes[0], jmpOpSize, &jmp64, jmpOpSize);
#pragma pack(pop)
		}
		for (DWORD x = 0u; x < hook->_allignmentBytes; x++)
			funcBytes[x + jmpOpSize] = 0xCC;

		NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pageptr, &thunkSize, oldProtect, &oldProtect);

		free(hook);

	}
	free(HookQueueArray);
	HookQueueArray = NULL;
	HookCount = 0u;
	ResumeProcess();
	return 0;
}

DWORD ProcessUnhookQueue()
{

	SuspendProcess();

	for (DWORD i = 0u; i < UnhookCount; i++)
	{
		struct HookChunk* hook = UnhookQueueArray[i];
		PVOID pageptr = hook->_functionPointer;
		SIZE_T thunkSize = hook->_allignmentBytes;
		ULONG oldProtect;
		NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pageptr, &thunkSize, PAGE_EXECUTE_READWRITE, &oldProtect);

		memcpy_s(hook->_functionPointer, hook->_allignmentBytes, hook->_trampolinePointer, hook->_allignmentBytes);

		NtFreeVirtualMemory(GetCurrentProcess(), &hook->_trampolinePointer, &hook->_trampolineAllocSize, MEM_RELEASE);

		NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pageptr, &thunkSize, oldProtect, &oldProtect);

		free(hook);

	}
	free(UnhookQueueArray);
	UnhookQueueArray = NULL;
	UnhookCount = 0u;
	ResumeProcess();
	return 0;
}

DWORD AttachHookVFTable(PVOID* funcPtr, PVOID hookPtr)
{
	// Is the engine running?
	if (!engineRunning)
		return -1;

	// Is this our first hook?
	if (!HookQueueArray)
		*(void**)&HookQueueArray = malloc(sizeof(void*));
	else
		*(void**)&HookQueueArray = realloc(HookQueueArray, sizeof(void*) * (HookCount + 1));

	struct HookChunk* pNewHook = (struct HookChunk*)malloc(sizeof(struct HookChunk));

	pNewHook->vft_hook = TRUE;
	pNewHook->_functionPointer = funcPtr;
	pNewHook->_hookPointer = hookPtr;
	HookQueueArray[HookCount++] = pNewHook;

	return 1;
}

DWORD DetachhHookVFTable(PVOID* funcPtr, PVOID hookPtr)
{
	return 1;
}

DWORD AttachHook(PVOID* funcPtr, PVOID hookPtr)
{
	// Is the engine running?
	if (!engineRunning)
		return -1;

	// Is this our first hook?
	if (!HookQueueArray)
		*(void**)&HookQueueArray = malloc(sizeof(void*));
	else
		*(void**)&HookQueueArray = realloc(HookQueueArray, sizeof(void*) * (HookCount + 1));

	int trampolineSize = 0u;
	PUCHAR nextInsn = (PUCHAR)funcPtr[0];

	// Parse asm until we have enough space for a jmp instruction.
	while (trampolineSize < jmpOpSize)
	{
		struct insn instruct = {0};
		insn_init(&instruct, nextInsn, is64Bit);
		insn_get_length(&instruct);
		trampolineSize += instruct.length;
		nextInsn += instruct.length;
	}

	PVOID trampPointer = NULL;
	SIZE_T trampAllocSize = trampolineSize;

	// Allocate a block of memory for our trampoline. Fill it with "int 3"
	NtAllocateVirtualMemory(GetCurrentProcess(), &trampPointer, 0u, &trampAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	FillMemory(trampPointer, trampAllocSize, 0xCC);

	// Copy the target function's asm into our trampoline.
	memcpy_s(trampPointer, trampolineSize, funcPtr[0], trampolineSize);

	// Append our jmp instruction to the trampoline.
	PUCHAR trampBytes = (PUCHAR)(trampPointer);
	if (!is64Bit) {
		trampBytes[trampolineSize] = 0xE9;
		((int*)&trampBytes[trampolineSize + 1])[0] = CalculateJmp((int)nextInsn, trampolineSize + (int)trampPointer);
	}
	else {
#pragma pack(push, 1)
		struct {
			uint8_t jmpFF;
			uint8_t jmp25;
			uint32_t zero;
			void* dest;
		} jmp64 = { 0xFF, 0x25, 0x00000000, nextInsn };
		memcpy_s(&trampBytes[trampolineSize], jmpOpSize, &jmp64, jmpOpSize);
#pragma pack(pop)
	}
	struct HookChunk* pNewHook = (struct HookChunk*)malloc(sizeof(struct HookChunk));

	InitHookChunk(pNewHook, funcPtr[0], trampPointer, hookPtr, trampolineSize - jmpOpSize, CalculateJmp((int)hookPtr, (int)funcPtr[0]), trampAllocSize);

	HookQueueArray[HookCount++] = pNewHook;

	funcPtr[0] = trampPointer;

	return 1;
}

DWORD StartHookEngine()
{
	if (!engineRunning)
	{
		//x86_init(opt_none, NULL, NULL);
		engineRunning = TRUE;
	}
	return engineRunning;
}

DWORD StopHookEngine()
{
	if (engineRunning)
	{
		//x86_cleanup();
		engineRunning = FALSE;
	}
	return !engineRunning;
}

DWORD DetachHook(PVOID* funcPtr, PVOID hookPtr)
{
	// Is the engine running?
	if (!engineRunning)
		return -1;

	// Is this our first hook?
	if (!UnhookQueueArray)
		*(void**)&UnhookQueueArray = malloc(4);
	else
		*(void**)&UnhookQueueArray = realloc(UnhookQueueArray, 4 * (UnhookCount + 1));

	DWORD trampolineSize = 0u;
	PUCHAR nextInsn = (PUCHAR)funcPtr[0];

	PVOID origFuncPtr;

	while (1)
	{
		struct insn instruct = {0};
		insn_init(&instruct, nextInsn, 0);
		insn_get_length(&instruct);
		insn_get_opcode(&instruct);

		if (instruct.opcode.value == 0xE9)
		{
			int jmpDistance = ((int*)&nextInsn[1])[0];
			nextInsn += instruct.length;
			origFuncPtr = &nextInsn[jmpDistance-trampolineSize];
			break;
		}
		trampolineSize += instruct.length;
		nextInsn += instruct.length;
	}

	MEMORY_BASIC_INFORMATION allocInfo;
	SIZE_T reqSize;
	NtQueryVirtualMemory(GetCurrentProcess(), funcPtr[0], MemoryBasicInformation, &allocInfo, sizeof(MEMORY_BASIC_INFORMATION), &reqSize);

	struct HookChunk* pNewHook = (struct HookChunk*)malloc(sizeof(struct HookChunk));

	InitHookChunk(pNewHook, origFuncPtr, funcPtr[0], hookPtr, trampolineSize, 0, allocInfo.RegionSize);

	UnhookQueueArray[UnhookCount++] = pNewHook;

	return 1;
}
