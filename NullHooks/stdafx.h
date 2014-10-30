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
#include "libdisasm/qword.h"
#include "libdisasm/x86_imm.h"
#include "libdisasm/ia32_insn.h"
#include "libdisasm/ia32_invariant.h"
#include "libdisasm/x86_operand_list.h"
#include "libdisasm/ia32_settings.h"
#include "libdisasm/ia32_reg.h"
#include "libdisasm/ia32_operand.h"
#include "libdisasm/ia32_modrm.h"
#include "libdisasm/ia32_opcode_tables.h"
#include "libdisasm/ia32_implicit.h"
#include "libdisasm/libdis.h"