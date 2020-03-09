#include <stdio.h>
#include "kernel.h"


const const wchar_t* device_name = L"\\\\.\\Nal";

void PrintErrorCode(int errorMsg, wchar_t* buf, int bufferSize)
{
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (bufferSize / sizeof(wchar_t)), NULL);

	return buf;
}

int main()
{
	do
	{
		HANDLE driverHandle = CreateFile(device_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (driverHandle == INVALID_HANDLE_VALUE)
		{
			wchar_t buf[256];
			int errorCode = GetLastError();
			PrintErrorCode(errorCode, buf, sizeof(buf));
			wprintf(L"UNABLE TO OPEN HANDLE TO VULNERABLE DRIVER: 0x%.8x %s\n", errorCode, buf);
			break;
		}
		DWORD ntosBase = GetNTKernelModuleAddress("win32base.sys");
		//printf("[+] Driver handle established at 0x:%p", driverHandle);

		//CloseHandle(driverHandle);
	} while (0);
	return 0;
}