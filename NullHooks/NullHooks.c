#include "stdafx.h"

#define InitHookChunk(o,a,b,c,d,e,f) o._functionPointer = a;\
	o._trampolinePointer = b;\
o._hookPointer = c;\
o._allignmentBytes = d;\
o._jmpDistance = e;\
o._trampolineAllocSize = f;

struct HookChunk
{
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

static int NTAPI CalculateJmp(int dest, int src)
{
	int jmpDest = dest;
	int jmpSrc = src + 5;
	return jmpDest - jmpSrc;
}

static BOOL NTAPI SuspendProcess()
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

static BOOL NTAPI ResumeProcess()
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

DWORD NTAPI SetHookThread(DWORD threadId)
{
	HookThread = threadId;
	return 0;
}

DWORD NTAPI ProcessHookQueue()
{

	SuspendProcess();

	for (DWORD i = 0u; i < HookCount; i++)
	{
		struct HookChunk* hook = HookQueueArray[i];
		PUCHAR funcBytes = (PUCHAR)hook->_functionPointer;
		PVOID pageptr = funcBytes;
		DWORD thunkSize = hook->_allignmentBytes + 5;
		ULONG oldProtect;
		NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pageptr, &thunkSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		funcBytes[0] = 0xE9;
		((int*)&funcBytes[1])[0] = hook->_jmpDistance;
		for (DWORD x = 0u; x < hook->_allignmentBytes; x++)
			funcBytes[x + 5] = 0xCC;

		NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pageptr, &thunkSize, oldProtect, &oldProtect);

		free(hook);

	}
	free(HookQueueArray);
	HookQueueArray = NULL;
	HookCount = 0u;
	ResumeProcess();
	return 0;
}

DWORD NTAPI ProcessUnhookQueue()
{

	SuspendProcess();

	for (DWORD i = 0u; i < UnhookCount; i++)
	{
		struct HookChunk* hook = UnhookQueueArray[i];
		PVOID pageptr = hook->_functionPointer;
		DWORD thunkSize = hook->_allignmentBytes;
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

static void x86dis_reporter(enum x86_report_codes code, void *arg, void *junk) {
	char * str;

	/* here we could examine the error and do something useful;
	* instead we just print that an error occurred */
	switch (code) {
	case report_disasm_bounds:
		str = "Attempt to disassemble RVA beyond end of buffer";
		break;
	case report_insn_bounds:
		str = "Instruction at RVA extends beyond buffer";
		break;
	case report_invalid_insn:
		str = "Invalid opcode at RVA";
		break;
	case report_unknown:
	default:	/* make GCC shut up */
		str = "Unknown Error";
		break;
	}

	//fprintf(info.err, "X86DIS ERROR \'%s:\' 0x%08" PRIXPTR"\n", str, (unsigned long)arg);
}

DWORD __fastcall AttachHook(PVOID* funcPtr, PVOID hookPtr)
{
	// Is the engine running?
	if (!engineRunning)
		return -1;

	// Is this our first hook?
	if (!HookQueueArray)
		*(void**)&HookQueueArray = malloc(4);
	else
		*(void**)&HookQueueArray = realloc(HookQueueArray, 4 * (HookCount + 1));

	DWORD trampolineSize = 0u;
	PUCHAR nextInsn = (PUCHAR)funcPtr[0];

	// Parse asm until we have enough space for a jmp instruction.
	while (trampolineSize < 5)
	{
		x86_insn_t insn;
		x86_disasm(nextInsn, 20, (uint32_t)nextInsn, 0, &insn);
		trampolineSize += insn.size;
		nextInsn += insn.size;
		x86_oplist_free(&insn);
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
	trampBytes[trampolineSize] = 0xE9;
	((int*)&trampBytes[trampolineSize + 1])[0] = CalculateJmp((int)nextInsn, trampolineSize + (int)trampPointer);

	struct HookChunk newHook;

	InitHookChunk(newHook, funcPtr[0], trampPointer, hookPtr, trampolineSize - 5, CalculateJmp((int)hookPtr, (int)funcPtr[0]), trampAllocSize);

	struct HookChunk* pNewHook = (struct HookChunk*)malloc(sizeof(struct HookChunk));
	pNewHook[0] = newHook;

	HookQueueArray[HookCount++] = pNewHook;

	funcPtr[0] = trampPointer;

	return 1;
}

DWORD NTAPI StartHookEngine()
{
	if (!engineRunning)
	{
		x86_init(opt_none, x86dis_reporter, NULL);
		engineRunning = TRUE;
	}
	return engineRunning;
}

DWORD NTAPI StopHookEngine()
{
	if (engineRunning)
	{
		x86_cleanup();
		engineRunning = FALSE;
	}
	return !engineRunning;
}

DWORD __fastcall DetachHook(PVOID* funcPtr, PVOID hookPtr)
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
		x86_insn_t insn;
		x86_disasm(nextInsn, 20, (uint32_t)nextInsn, 0, &insn);
		if ((insn.type == insn_jmp) && (insn.size == 5u))
		{
			int jmpDistance = ((int*)&nextInsn[1])[0];
			nextInsn += insn.size;
			origFuncPtr = &nextInsn[jmpDistance-trampolineSize];
			x86_oplist_free(&insn);
			break;
		}
		trampolineSize += insn.size;
		nextInsn += insn.size;
		x86_oplist_free(&insn);
	}

	MEMORY_BASIC_INFORMATION allocInfo;
	SIZE_T reqSize;
	NtQueryVirtualMemory(GetCurrentProcess(), funcPtr[0], MemoryBasicInformation, &allocInfo, sizeof(MEMORY_BASIC_INFORMATION), &reqSize);

	struct HookChunk newHook;

	InitHookChunk(newHook, origFuncPtr, funcPtr[0], hookPtr, trampolineSize, 0, allocInfo.RegionSize);

	struct HookChunk* pNewHook = (struct HookChunk*)malloc(sizeof(struct HookChunk));
	pNewHook[0] = newHook;

	UnhookQueueArray[UnhookCount++] = pNewHook;

	return 1;
}
