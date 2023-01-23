#pragma once
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <fstream>
#include <TlHelp32.h>
#include "MemMan.h"

namespace HelperFunctions {
	DWORD64 FindPatternExModule(HANDLE h_process, const wchar_t* exe_name, const char* signature, MODULEENTRY32 mod_entry);
	MODULEENTRY32 GetModule(DWORD64 procID, const wchar_t* modName);
}