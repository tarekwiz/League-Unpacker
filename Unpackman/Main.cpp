#include <Windows.h>
#include <cstdio>

typedef NTSTATUS(__stdcall* ZwRaiseException_t)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ThreadContext, BOOLEAN HandleException);
ZwRaiseException_t raiseExceptionFunc;

void PrintSingleCharacter(char c)
{
	DWORD written;
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), &c, 1, &written, NULL);
}

void PrintMessage(const char* fmt, ...)
{
	char buf[4096];
	va_list args;
	va_start(args, fmt);
	vsnprintf_s(buf, 4096, fmt, args);
	char* bufptr = buf;
	while (*bufptr)
	{
		if (*bufptr == '~')
		{
			++bufptr;
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), *bufptr);
		}
		else
		{
			PrintSingleCharacter(*bufptr);
		}
		++bufptr;
	}
	PrintSingleCharacter('\n');
	va_end(args);
}

__declspec(naked) void FinishThread()
{
	__asm {
		push 0 // STATUS_SUCCESS
		push -2 // ZwCurrentThread()
		call TerminateThread
	}
}

unsigned char codeBuf[52428800];
unsigned char leagueBuf[52428800];

DWORD_PTR baseTextAddress = 0;

DWORD WINAPI GetProtectedMemory(PVOID Address)
{
	CONTEXT ctx;
	EXCEPTION_RECORD exr;

	MEMORY_BASIC_INFORMATION mbi;
	memset(&mbi, 0, sizeof(mbi));
	VirtualQuery(Address, &mbi, sizeof(mbi));

	if (mbi.Protect == PAGE_NOACCESS)
	{
		RtlCaptureContext(&ctx);

		memset(&exr, 0, sizeof(EXCEPTION_RECORD));

		ctx.Eip = (DWORD)FinishThread;
		exr.ExceptionAddress = (PVOID)Address;
		exr.NumberParameters = 2;
		exr.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
		exr.ExceptionInformation[1] = (ULONG_PTR)Address;

		raiseExceptionFunc(&exr, &ctx, 1);
	}

	TerminateThread(GetCurrentThread(), 0);
	return 0;
}

void EnsureMemoryIsDecrypted(PVOID Address)
{
	HANDLE hThread = CreateThread(NULL, 0, GetProtectedMemory, Address, NULL, 0);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
}

DWORD WINAPI DoStuff(LPVOID lpParameter)
{
	AllocConsole();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	DWORD textPageCount = 0;

	PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleA(NULL);
	PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageDosHeader + imageDosHeader->e_lfanew);
	DWORD sectionCount = imageNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER imageSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)&imageNtHeaders->OptionalHeader + imageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < sectionCount; ++i)
	{
		if (strcmp((const char*)(imageSection + i)->Name, ".text") == 0)
		{
			baseTextAddress = (DWORD_PTR)imageDosHeader + (imageSection + i)->PointerToRawData;
			textPageCount = (imageSection + i)->SizeOfRawData / 0x1000;
			break;
		}
	}

	for (DWORD i = 0; i < textPageCount; ++i)
	{
		LPVOID mem = (LPVOID)(baseTextAddress + i * 0x1000);
		EnsureMemoryIsDecrypted(mem);
		memcpy((unsigned char*)codeBuf + ((DWORD_PTR)mem - baseTextAddress), mem, 0x1000);

		if ((i + 1) % 200 == 0 || i + 1 == textPageCount)
			PrintMessage("Sections decrypted: ~%c%d/%d~%c", 11, i + 1, textPageCount, 15);
	}

	DWORD fileWritten;
	HANDLE hFile = CreateFileA("League of Legends.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	DWORD leagueExeSize = GetFileSize(hFile, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD read;
		ReadFile(hFile, leagueBuf, leagueExeSize, &read, NULL);
		CloseHandle(hFile);

		hFile = CreateFileA("League of Legends_decrypted.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			memcpy(leagueBuf + (baseTextAddress - (DWORD_PTR)imageDosHeader), codeBuf, textPageCount * 0x1000);
			WriteFile(hFile, leagueBuf, leagueExeSize, &fileWritten, NULL);

			PrintMessage("===============================================================================");
			PrintMessage("Base address: ~%c0x%08x~%c", 11, imageDosHeader, 15);
			PrintMessage("~%cAll sections dumped~%c: decrypted .exe in:", 10, 15);

			char fileNameBuf[512];
			memset(fileNameBuf, 0, sizeof(fileNameBuf));
			GetFinalPathNameByHandleA(hFile, fileNameBuf, 512, 0);
			PrintMessage("~%c%s~%c", 11, fileNameBuf, 15);

			CloseHandle(hFile);
		}
	}
	

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		raiseExceptionFunc = (ZwRaiseException_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRaiseException");
		CloseHandle(CreateThread(NULL, 0, DoStuff, NULL, 0, NULL));
	}
	return TRUE;
}
