#include "vuln_driver.h"

using namespace kernel;


void PrintErrorCode(int errorMsg, char* buf, int bufferSize)
{
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (bufferSize / sizeof(wchar_t)), NULL);

}

vulnerable_driver::vulnerable_driver(const std::string& device_name)
{
	driver_handle = CreateFile(device_name.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver_handle== INVALID_HANDLE_VALUE)
	{
		char buf[256];
		int errorCode = GetLastError();
		PrintErrorCode(errorCode, buf, sizeof(buf));
		printf("UNABLE TO OPEN HANDLE TO VULNERABLE DRIVER: 0x%.8x %s\n", errorCode, buf);
	}
}