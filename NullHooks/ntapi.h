/*
* Internal NT APIs and data structures
*
* Copyright (C) the Wine project
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef __WINE_WINTERNL_H
#define __WINE_WINTERNL_H

#define InitializeObjectAttributes(o,n,a,r,s)\
(&o)->Length = sizeof(OBJECT_ATTRIBUTES);\
(&o)->RootDirectory = r;\
(&o)->Attributes = a;\
(&o)->ObjectName = n;\
(&o)->SecurityDescriptor = s;\
(&o)->SecurityQualityOfService = NULL;

#include <windef.h>


	/**********************************************************************
	* Fundamental types and data structures
	*/

	typedef LONG NTSTATUS, *PNTSTATUS;

	typedef CONST char *PCSZ;

	typedef short CSHORT;
	typedef CSHORT *PCSHORT;

	typedef struct _STRING {
		USHORT Length;
		USHORT MaximumLength;
		PCHAR Buffer;
	} STRING, *PSTRING;

	typedef STRING ANSI_STRING;
	typedef PSTRING PANSI_STRING;
	typedef const STRING *PCANSI_STRING;

	typedef STRING OEM_STRING;
	typedef PSTRING POEM_STRING;
	typedef const STRING *PCOEM_STRING;

	typedef struct _UNICODE_STRING {
		USHORT Length;        /* bytes */
		USHORT MaximumLength; /* bytes */
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation,
		MemoryWorkingSetList,
		MemorySectionName,
		MemoryBasicVlmInformation
	} MEMORY_INFORMATION_CLASS;

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;       /* type SECURITY_DESCRIPTOR */
		PVOID SecurityQualityOfService; /* type SECURITY_QUALITY_OF_SERVICE */
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	NTSTATUS  WINAPI NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG, SIZE_T*, ULONG, ULONG);
	NTSTATUS  WINAPI NtClose(HANDLE);
	NTSTATUS  WINAPI NtFreeVirtualMemory(HANDLE, PVOID*, SIZE_T*, ULONG);
	NTSTATUS  WINAPI NtOpenThread(HANDLE*, ACCESS_MASK, const OBJECT_ATTRIBUTES*, const CLIENT_ID*);
	NTSTATUS  WINAPI NtProtectVirtualMemory(HANDLE, PVOID*, SIZE_T*, ULONG, ULONG*);
	NTSTATUS  WINAPI NtQueryVirtualMemory(HANDLE, LPCVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, SIZE_T*);
	NTSTATUS  WINAPI NtResumeThread(HANDLE, PULONG);
	NTSTATUS  WINAPI NtSuspendThread(HANDLE, PULONG);

#define NtCurrentProcess() ((HANDLE)-1)

#ifndef RtlFillMemory
#define RtlFillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))
#endif
#ifndef RtlMoveMemory
#define RtlMoveMemory(Destination,Source,Length) memmove((Destination),(Source),(Length))
#endif
#define RtlStoreUlong(p,v)  do { ULONG _v = (v); memcpy((p), &_v, sizeof(_v)); } while (0)
#define RtlStoreUlonglong(p,v) do { ULONGLONG _v = (v); memcpy((p), &_v, sizeof(_v)); } while (0)
#define RtlRetrieveUlong(p,s) memcpy((p), (s), sizeof(ULONG))
#define RtlRetrieveUlonglong(p,s) memcpy((p), (s), sizeof(ULONGLONG))
#ifndef RtlZeroMemory
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))
#endif

#endif  /* __WINE_WINTERNL_H */