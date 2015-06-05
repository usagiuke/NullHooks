// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib,"ntdll.lib")
#include "ntapi.h"
#include "NullHooks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>