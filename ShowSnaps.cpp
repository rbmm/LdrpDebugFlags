#include "stdafx.h"

_NT_BEGIN

struct SLog 
{
	enum { cb_buf = 0x100000 };

	PVOID _BaseAddress = AllocBuf();
	ULONG _Ptr, _cch;

	PVOID AllocBuf()
	{
		_Ptr = 0, _cch = 0;

		if (PVOID BaseAddress = LocalAlloc(LMEM_FIXED, cb_buf))
		{
			_cch = cb_buf;
			return BaseAddress;
		}

		return 0;
	}

	~SLog()
	{
		if (PVOID BaseAddress = _BaseAddress)
		{
			LocalFree(BaseAddress);
		}
	}

	PSTR buf()
	{
		return (PSTR)_BaseAddress + _Ptr;
	}

	void addbuf(int cch)
	{
		if (0 < cch)
		{
			_cch -= cch, _Ptr += cch;
		}
	}

	void operator()(const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);
		addbuf(_vsnprintf(buf(), _cch, format, argptr));
		va_end(argptr);
	}

	void operator <<(PCSTR psz)
	{
		size_t len = strlen(psz);
		if (!memcpy_s(buf(), _cch, psz, len))
		{
			addbuf((ULONG)len);
		}
	}

	void operator <<(PCWSTR psz)
	{
		addbuf(WideCharToMultiByte(CP_UTF8, 0, psz, (ULONG)wcslen(psz), buf(), _cch, 0, 0));
	}

	void reset()
	{
		_Ptr = 0, _cch = _BaseAddress ? cb_buf : 0;
	}
};

struct YProcess : LIST_ENTRY
{
	SLog log;
	HANDLE hProcess;
	HANDLE UniqueProcess;
	HANDLE hLog = 0;
	LONG dwFlags = 0;

	enum {
		eBreak, eWowBreak
	};

	YProcess(HANDLE hProcess, HANDLE UniqueProcess) : hProcess(hProcess), UniqueProcess(UniqueProcess)
	{
		WCHAR sz[128];
		SYSTEMTIME time;
		GetLocalTime(&time);

		if (0 < swprintf_s(sz, _countof(sz), L"%04x[%u-%02u-%02u %02u#%02u#%02u#%03u]", (ULONG)(ULONG_PTR)UniqueProcess, 
			time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds))
		{
			HANDLE hFile = CreateFileW(sz, FILE_APPEND_DATA, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
			if (INVALID_HANDLE_VALUE != hFile)
			{
				hLog = hFile;
			}
		}
	}

	~YProcess()
	{
		if (HANDLE hFile = hLog)
		{
			flush();
			NtClose(hFile);
		}
		NtClose(hProcess);
	}

	void flush(ULONG dwFreeSpace = MAXULONG)
	{
		if (ULONG Ptr = log._Ptr)
		{
			if (log._cch < dwFreeSpace)
			{
				if (HANDLE hFile = hLog)
				{
					WriteFile(hFile, log._BaseAddress, Ptr, &Ptr, 0);
				}

				log.reset();
			}
		}
	}
};

struct YProcessList : LIST_ENTRY 
{
	ULONG nProcessCount = 0;

	YProcessList()
	{
		Flink = this, Blink = this;
	}

	~YProcessList()
	{
		PLIST_ENTRY Entry = Flink;

		while (Entry != this)
		{
			YProcess* process = static_cast<YProcess*>(Entry);

			Entry = Entry->Flink;

			delete process;
		}
	}

	bool IsLogNotEmpty()
	{
		PLIST_ENTRY Entry = this;

		while ((Entry = Entry->Flink) != this)
		{
			if (static_cast<YProcess*>(Entry)->log._Ptr)
			{
				return true;
			}
		}

		return false;
	}

	void flush(ULONG dwFreeSpace = MAXULONG)
	{
		PLIST_ENTRY Entry = this;

		while ((Entry = Entry->Flink) != this)
		{
			static_cast<YProcess*>(Entry)->flush(dwFreeSpace);
		}
	}

	YProcess* operator[](HANDLE UniqueProcess)
	{
		PLIST_ENTRY Entry = this;

		while ((Entry = Entry->Flink) != this)
		{
			if (static_cast<YProcess*>(Entry)->UniqueProcess == UniqueProcess)
			{
				return static_cast<YProcess*>(Entry);
			}
		}

		return 0;
	}

	YProcess* operator()(HANDLE hProcess, HANDLE UniqueProcess)
	{
		if (YProcess* process = new YProcess(hProcess, UniqueProcess))
		{
			InsertHeadList(this, process);
			nProcessCount++;
			return process;
		}
		return 0;
	}

	void operator >>(YProcess* process)
	{
		--nProcessCount;
		RemoveEntryList(process);
		delete process;
	}

	operator bool ()
	{
		return nProcessCount != 0;
	}
};

void PrintFileName(SLog& log, HANDLE FileHandle, PVOID Buffer, ULONG Length)
{
	if (FileHandle)
	{
		NTSTATUS status = NtQueryObject(FileHandle, ObjectNameInformation, Buffer, Length, &Length);
		if (0 > status)
		{
			log("\tNtQueryObject = %x\r\n", status);
		}
		else
		{
			log("\tFile: %wZ\r\n", &reinterpret_cast<POBJECT_NAME_INFORMATION>(Buffer)->Name);
		}
	}
}

void PrintFileName(SLog& log, HANDLE hProcess, PVOID NamePointer, PVOID Buffer, ULONG Length)
{
	if (0 <= ZwReadVirtualMemory(hProcess, NamePointer, &NamePointer, sizeof(PVOID), 0))
	{
		if (!((ULONG_PTR)NamePointer  & (__alignof(WCHAR) - 1)))
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (0 <= ZwQueryVirtualMemory(hProcess, NamePointer, MemoryBasicInformation, &mbi, sizeof(mbi), 0))
			{
				mbi.RegionSize -= (ULONG_PTR)NamePointer - (ULONG_PTR)mbi.BaseAddress;
				switch (ZwReadVirtualMemory(hProcess, NamePointer, Buffer, min(Length, mbi.RegionSize), &mbi.RegionSize))
				{
				case STATUS_SUCCESS:
				case STATUS_PARTIAL_COPY:
					if (sizeof(WCHAR) < mbi.RegionSize)
					{
						*(WCHAR*)RtlOffsetToPointer(Buffer, mbi.RegionSize - sizeof(WCHAR)) = 0;
						log("\tWin32File: %S\r\n", Buffer);
					}
					break;
				}
			}
		}
	}
}

void OnDebugPrint(SLog& log, HANDLE hProcess, PEXCEPTION_RECORD ExceptionRecord, PVOID Buffer, ULONG Length)
{
	if (1 < ExceptionRecord->NumberParameters)
	{
		SIZE_T cch = ExceptionRecord->ExceptionInformation[0];
		PVOID psz = (PVOID)ExceptionRecord->ExceptionInformation[1];

		if (cch && cch < Length)
		{
			BOOL bWide = FALSE;

			if (ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C)
			{
				if (3 < ExceptionRecord->NumberParameters)
				{
					cch = ExceptionRecord->ExceptionInformation[2];
					psz = (PVOID)ExceptionRecord->ExceptionInformation[3];
				}
				else
				{
					cch *= sizeof(WCHAR);
					bWide = TRUE;
				}
			}

			if (0 <= ZwReadVirtualMemory(hProcess, psz, Buffer, cch, &cch) && cch)
			{
				if (bWide)
				{
					((PWSTR)Buffer)[cch / sizeof(WCHAR) - 1] = 0;
					log << (PWSTR)Buffer;
				}
				else
				{
					((PSTR)Buffer)[cch - 1] = 0;
					log << (PSTR)Buffer;
				}

				log << "\r\n";
			}
		}
	}
}

BOOLEAN StopDebugging ( HANDLE hProcess)
{
	HANDLE hProcess2;
	if (0 <= ZwDuplicateObject(NtCurrentProcess(), hProcess, NtCurrentProcess(), &hProcess2, PROCESS_SUSPEND_RESUME, 0, 0))
	{
		NTSTATUS status = DbgUiStopDebugging(hProcess2);
		NtClose(hProcess2);
		if (0 <= status)
		{
			return FALSE;
		}
	}

	ZwTerminateProcess(hProcess, 0);

	return TRUE;
}

void SetGlobalFlags(HANDLE hProcess, PVOID buf)
{
	ULONG NtGlobalFlags;
	if (0 <= ZwReadVirtualMemory(hProcess, buf, &NtGlobalFlags, sizeof(NtGlobalFlags), 0))
	{
		NtGlobalFlags |= 2;
		ZwWriteVirtualMemory(hProcess, buf, &NtGlobalFlags, sizeof(NtGlobalFlags), 0);
	}
}

void SetGlobalFlags(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;

	if (0 <= NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0))
	{
		SetGlobalFlags(hProcess, &reinterpret_cast<_PEB*>(pbi.PebBaseAddress)->NtGlobalFlag);
	}

	struct PEB32 {
		UCHAR pad[0x68];
		ULONG NtGlobalFlag;
	}* WowPeb;

	if (0 <= NtQueryInformationProcess(hProcess, ProcessWow64Information, &WowPeb, sizeof(WowPeb), 0) && WowPeb)
	{
		SetGlobalFlags(hProcess, &reinterpret_cast<PEB32*>(WowPeb)->NtGlobalFlag);
	}
}

NTSTATUS OnRemoteView(_In_ PCLIENT_ID cid, _In_ BOOL bUnmap, _Out_ PULONG_PTR UniqueProcessId)
{
	NTSTATUS status;
	HANDLE hObject, hProcess;
	static const OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
	if (0 <= (status = ZwOpenThread(&hObject, THREAD_GET_CONTEXT, const_cast<POBJECT_ATTRIBUTES>(&zoa), cid)))
	{
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_INTEGER;
		status = ZwGetContextThread(hObject, &ctx);
		NtClose(hObject);
		if (0 <= status && 0 <= (status = NtOpenProcess(&hObject, PROCESS_DUP_HANDLE, const_cast<POBJECT_ATTRIBUTES>(&zoa), cid)))
		{
			status = ZwDuplicateObject(hObject, (HANDLE)(bUnmap ? ctx.Rcx : ctx.Rdx), 
				NtCurrentProcess(), &hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0);
			NtClose(hObject);

			if (0 <= status)
			{
				PROCESS_BASIC_INFORMATION pbi;
				status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
				NtClose(hProcess);
				if (0 <= status)
				{
					*UniqueProcessId = pbi.UniqueProcessId;
				}
			}
		}
	}

	return status;
}

void runDebugLoop(PVOID Buffer, ULONG Length)
{
	YProcessList List;

	NTSTATUS status;

	DBGUI_WAIT_STATE_CHANGE StateChange;

	BOOLEAN bContinue;

	LARGE_INTEGER timeout = { (ULONG)-10000000, -1 }; // 1 sec
	do 
	{
		if (0 > (status = DbgUiWaitStateChange(&StateChange, List.IsLogNotEmpty() ? &timeout : 0)))
		{
			break;
		}

		if (status == STATUS_TIMEOUT)
		{
			List.flush();
			bContinue = FALSE;
			continue;
		}

		List.flush(MAXUSHORT);

		status = DBG_CONTINUE, bContinue = TRUE;

		YProcess* process = List[StateChange.AppClientId.UniqueProcess];

		if (!process)
		{
			ULONG_PTR UniqueProcessId;

			switch (StateChange.NewState)
			{
			case DbgCreateProcessStateChange:

				NtClose(StateChange.CreateProcessInfo.HandleToThread);

				if (process = List(StateChange.CreateProcessInfo.HandleToProcess, StateChange.AppClientId.UniqueProcess))
				{
					SLog& log = process->log;

					log("%04x:%04x # CreateProcess<%p> %p %p\r\n", 
						(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
						(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
						StateChange.AppClientId.UniqueProcess,
						StateChange.CreateProcessInfo.NewProcess.BaseOfImage,
						StateChange.CreateThread.NewThread.StartAddress);

					PrintFileName(log, StateChange.CreateProcessInfo.NewProcess.FileHandle, Buffer, Length);
					SetGlobalFlags(process->hProcess);
				}
				else
				{
					bContinue = StopDebugging(StateChange.CreateProcessInfo.HandleToProcess);
					NtClose(StateChange.CreateProcessInfo.HandleToProcess);
				}

				NtClose(StateChange.CreateProcessInfo.NewProcess.FileHandle);

				break;

			case DbgCreateThreadStateChange:
				NtClose(StateChange.CreateThread.HandleToThread);
				break;

			case DbgLoadDllStateChange:
				if (0 <= OnRemoteView(&StateChange.AppClientId, FALSE, &UniqueProcessId))
				{
					if (process = List[(HANDLE)UniqueProcessId])
					{
						process->log("%04x:%04x # Remote Image Mapping: %p\n", 
							(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
							(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
							StateChange.LoadDll.BaseOfDll);

						PrintFileName(process->log, StateChange.LoadDll.FileHandle, Buffer, Length);
					}
				}
				NtClose(StateChange.LoadDll.FileHandle);
				break;

			case DbgUnloadDllStateChange:
				if (0 <= OnRemoteView(&StateChange.AppClientId, TRUE, &UniqueProcessId))
				{
					if (process = List[(HANDLE)UniqueProcessId])
					{
						process->log("%04x:%04x # Remote Image UnMapping: %p\n", 
							(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
							(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
							StateChange.UnloadDll.BaseAddress);

						DbgPrint("%04x:%04x # Remote Image UnMapping: %p\n", 
							(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
							(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread);
					}
				}

				break;
			}

			continue;
		}

		SLog& log = process->log;
		HANDLE hProcess = process->hProcess;
		LONG i;
		CHAR c;

		switch(StateChange.NewState)
		{
		case DbgBreakpointStateChange:
		case DbgSingleStepStateChange:
		case DbgExceptionStateChange:

			status = DBG_EXCEPTION_NOT_HANDLED;

			i = YProcess::eBreak, c = 'A';
			switch (StateChange.Exception.ExceptionRecord.ExceptionCode)
			{
			case STATUS_WX86_BREAKPOINT:
				i = YProcess::eWowBreak;
			case STATUS_BREAKPOINT:
				if (!_bittestandset(&process->dwFlags, i))
				{
					status = DBG_CONTINUE;
				}
				break;

			case DBG_PRINTEXCEPTION_WIDE_C:
				c = 'W';
			case DBG_PRINTEXCEPTION_C:
				log("%04x:%04x # DBG_PRINT_%c\r\n", 
					(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
					(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
					c);
				OnDebugPrint(log, hProcess, &StateChange.Exception.ExceptionRecord, Buffer, Length);
				status = DBG_CONTINUE;
				break;
			}

			if (status != DBG_CONTINUE)
			{
				log("%04x:%04x # Exception<%x> %x at %p\r\n", 
					(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
					(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
					StateChange.Exception.FirstChance,
					StateChange.Exception.ExceptionRecord.ExceptionCode,
					StateChange.Exception.ExceptionRecord.ExceptionAddress);

				if (!StateChange.Exception.FirstChance)
				{
					bContinue = StopDebugging(hProcess);
					List >> process;
				}
			}
			break;

		case DbgCreateProcessStateChange:
			__debugbreak();
			break;

		case DbgCreateThreadStateChange:
			log("%04x:%04x # CreateThread<%p> %p\r\n", 
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
				StateChange.AppClientId.UniqueThread, 
				StateChange.CreateThread.NewThread.StartAddress);
			NtClose(StateChange.CreateThread.HandleToThread);
			break;

		case DbgExitThreadStateChange:
			log("%04x:%04x # ExitThread<%p> %x\r\n", 
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
				StateChange.AppClientId.UniqueThread, 
				StateChange.ExitThread.ExitStatus);
			break;

		case DbgLoadDllStateChange:
			log("%04x:%04x # LoadDll:%p\r\n", 
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
				StateChange.LoadDll.BaseOfDll);
			PrintFileName(log, StateChange.LoadDll.FileHandle, Buffer, Length);
			NtClose(StateChange.LoadDll.FileHandle);
			if (StateChange.LoadDll.NamePointer)
			{
				PrintFileName(log, hProcess, StateChange.LoadDll.NamePointer, Buffer, Length);
			}
			break;

		case DbgUnloadDllStateChange:
			log("%04x:%04x # UnloadDll:%p\r\n", 
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
				StateChange.UnloadDll.BaseAddress);
			break;

		case DbgExitProcessStateChange:
			log("%04x:%04x # ExitProcess %x\r\n", 
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueProcess,
				(ULONG)(ULONG_PTR)StateChange.AppClientId.UniqueThread,
				StateChange.ExitProcess.ExitStatus);
			List >> process;
			break;
		}

	} while ((!bContinue || 0 <= (status = DbgUiContinue(&StateChange.AppClientId, status))) && List);
}

HRESULT StartDebugger(PCWSTR lpApplicationName, PCWSTR lpCommandLine)
{
	HANDLE hDbgObj;
	STATIC_OBJECT_ATTRIBUTES_EX(oa, "\\BaseNamedObjects\\Restricted\\9F36DE8241F9A73F1B6F85CEB935", OBJ_OPENIF|OBJ_CASE_INSENSITIVE, 0, 0);
	
	NTSTATUS status = NtCreateDebugObject(&hDbgObj, DEBUG_ALL_ACCESS, &oa, DEBUG_KILL_ON_CLOSE);
	
	if (0 > status)
	{
		status |= FACILITY_NT_BIT;
	}
	else
	{
		DbgUiSetThreadDebugObject(hDbgObj);

		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi;
		if (CreateProcessW(lpApplicationName, const_cast<PWSTR>(lpCommandLine), 0, 0, FALSE, DEBUG_PROCESS, 0, 0, &si, &pi))
		{
			NtClose(pi.hProcess);
			NtClose(pi.hThread);

			if (status != STATUS_OBJECT_NAME_EXISTS)
			{
				if (PUCHAR buf = new UCHAR [MAXUSHORT + 1])
				{
					runDebugLoop(buf, MAXUSHORT + 1);
					delete [] buf;
				}
				else
				{
					status = STATUS_NO_MEMORY;
				}
			}
		}
		else
		{
			status = RtlGetLastNtStatus();
			ULONG dwError = GetLastError();
			status = RtlNtStatusToDosError(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
		}

		DbgUiSetThreadDebugObject(0);

		NtClose(hDbgObj);
	}

	return status;
}

BOOL IsEscape(PWSTR lpsz, PWSTR* lplpsz)
{
	ULONG n = 0;
	while (*++lpsz=='*')
	{
		++n;
	}
	*lplpsz = lpsz;
	return n & 1;
}

PWSTR UnEscape(PWSTR lpsz)
{
	PWSTR sz = lpsz, qz = sz;
	WCHAR c;
	do 
	{
		c = *lpsz++;
		if (c == '*')
		{
			lpsz++;
		}
		*sz++ = c;
	} while (c);
	return qz;
}

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
	int r = -1;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBoxW(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

void WINAPI ep(PWSTR lpe)
{
	PWSTR buf[2], *argv = buf, lpsz = GetCommandLineW();

	int argc = 0;

	while (lpsz = wcschr(lpsz, L'*'))
	{
		if (IsEscape(lpsz, &lpe))
		{
			lpsz = lpe;
			continue;
		}

		*lpsz++ = 0;

		*argv++ = lpsz;

		if (_countof(buf) < ++argc)
		{
			break;
		}
	}

	HRESULT hr = argc == 2 ? StartDebugger(UnEscape(buf[0]), UnEscape(buf[1])) : HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);

	ShowErrorBox(0, hr, L"ShowSnaps( LdrpDebugFlags )", 0 > hr ? MB_ICONHAND : MB_ICONINFORMATION);

	ExitProcess(0);
}

_NT_END

