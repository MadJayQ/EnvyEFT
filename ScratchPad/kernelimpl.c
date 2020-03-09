#include "kernel.h"

#include <stdio.h>

//GetNTKernelModuleAddress uses NtQuerySystemInformation to leak the address of kernel module addresses

DWORD64 GetNTKernelModuleAddress(const char* moduleName)
{
	PVOID64 systemInformationBuffer = NULL;
	DWORD bufferSize = 0UL;
	NTSTATUS queryStatus = NtQuerySystemInformation(
		SystemModuleInformation,
		systemInformationBuffer,
		bufferSize,
		&bufferSize
	);

	while (queryStatus == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(systemInformationBuffer, 0, MEM_RELEASE);
		systemInformationBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		queryStatus = NtQuerySystemInformation(SystemModuleInformation, systemInformationBuffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(queryStatus))
	{
		VirtualFree(systemInformationBuffer, 0, MEM_RELEASE);
		return 0;
	}
	//List of process modules exists at SystemInformationBuffer+0x0
	PRTL_PROCESS_MODULES processModules = (PRTL_PROCESS_MODULES)(systemInformationBuffer);
	DWORD64 targetAddress = NULL;
	UINT moduleIdx = 0;
	for (moduleIdx; moduleIdx < processModules->NumberOfModules; ++moduleIdx)
	{
		RTL_PROCESS_MODULE_INFORMATION* moduleInformation = &processModules->Modules[moduleIdx];
		char* currentModuleName = (char*)(moduleInformation->FullPathName + moduleInformation->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName))
		{
			DWORD64 targetAddr = moduleInformation->ImageBase;
			break;
		}
	}

	VirtualFree(systemInformationBuffer, 0, MEM_RELEASE);
	return targetAddress;
}