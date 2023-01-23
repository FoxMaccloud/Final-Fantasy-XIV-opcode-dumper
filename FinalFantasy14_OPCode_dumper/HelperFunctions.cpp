#include "HelperFunctions.h"


namespace HelperFunctions {

	DWORD64 FindPattern(char* base, size_t sizeOfImage, const char* signature)
	{
		static auto pattern_to_byte = [](const char* pattern) {
			auto bytes = std::vector<char>{};
			auto start = const_cast<char*>(pattern);
			auto end = const_cast<char*>(pattern) + strlen(pattern);

			for (auto current = start; current < end; ++current) {
				if (*current == '?') {
					++current;
					if (*current == '?')
						++current;
					bytes.push_back('\?');
				}
				else {
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

		auto patternBytes = pattern_to_byte(signature);
		DWORD64 patternLength = patternBytes.size();
		auto data = patternBytes.data();

		for (DWORD64 i = 0; i < sizeOfImage - patternLength; i++)
		{
			bool found = true;
			for (DWORD64 j = 0; j < patternLength; j++)
			{
				char a = '\?';
				char b = *(char*)(base + i + j);
				found &= data[j] == a || data[j] == b;
			}
			if (found)
			{
				return (DWORD64)base + i;
			}
		}
		return NULL;
	}

	DWORD64 FindPatternEx(HANDLE h_process, DWORD64 begin, DWORD64 end, const char* signature)
	{
		size_t bytes_read;

		while (begin < end)
		{
			char buffer[4096];
			DWORD old_protect;
			VirtualProtectEx(h_process, (void*)begin, sizeof(buffer), PROCESS_VM_READ, &old_protect);
			ReadProcessMemory(h_process, (void*)begin, &buffer, sizeof(buffer), &bytes_read);
			VirtualProtectEx(h_process, (void*)begin, sizeof(buffer), old_protect, NULL);

			if (bytes_read == 0)
			{
				return NULL;
			}
			DWORD64 internal_address = FindPattern((char*)&buffer, bytes_read, signature);
			if (internal_address != NULL)
			{
				// internal to external
				DWORD64 offset_from_buffer = (DWORD64)internal_address - (DWORD64)&buffer;
				return (DWORD64)(begin + offset_from_buffer);
			}
			else
			{
				begin = begin + bytes_read;
			}
		}
		return NULL;
	}

	DWORD64 FindPatternExModule(HANDLE h_process, const wchar_t* exe_name, const char* pattern, MODULEENTRY32 mod_entry)
	{
		DWORD64 begin = (DWORD64)mod_entry.modBaseAddr;
		DWORD64 end = begin + mod_entry.modBaseSize;
		
		return FindPatternEx(h_process, begin, end, pattern);
	}

	MODULEENTRY32 GetModule(DWORD64 procID, const wchar_t* modName)
	{
		MODULEENTRY32 modEntry = { 0 };

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);

		if (snapshot != INVALID_HANDLE_VALUE)
		{
			modEntry.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(snapshot, &modEntry))
			{
				do
				{
					if (!wcscmp(modEntry.szModule, modName))
					{
						break;
					}
				} while (Module32Next(snapshot, &modEntry));
			}
			CloseHandle(snapshot);
		}
		return modEntry;
	}
}