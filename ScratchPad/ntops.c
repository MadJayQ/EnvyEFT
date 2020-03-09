#include "ntops.h"

__NtQuerySystemInformation _NtQuerySystemInformation;
__NtDuplicateObject _NtDuplicateObject;
__NtQueryObject _NtQueryObject;
__NtCreateSection _NtCreateSection;
__NtMapViewOfSection _NtMapViewOfSection;
__NtUnmapViewOfSection _NtUnmapViewOfSection;
__NtCreateEvent _NtCreateEvent;
__NtQueryInformationProcess _NtQueryInformationProcess;
__RtlInitUnicodeString _RtlInitUnicodeString;
__RtlFreeUnicodeString _RtlFreeUnicodeString;
__RtlNtStatusToDosError _RtlNtStatusToDosError;
__RtlDosApplyFileIsolationRedirection_Ustr _RtlDosApplyFileIsolationRedirection_Ustr;

PVOID
GetLibraryProcAdr(
	const char* name,
	const char* proc
)
{
	return GetProcAddress(
		GetModuleHandleA(name),
		proc
	);
}

NTSTATUS
NTAPI
NtQuerySystemInformation(
	_In_      ULONG		SystemInformationClass,
	_Inout_   PVOID		SystemInformation,
	_In_      ULONG		SystemInformationLength,
	_Out_opt_ PULONG	ReturnLength
)
{
	GET_SYSTEM_ROUTINE(NtQuerySystemInformation);
	return _NtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);
}

NTSTATUS
NTAPI
NtDuplicateObject(
	_In_      HANDLE      SourceProcessHandle,
	_In_      HANDLE      SourceHandle,
	_In_opt_  HANDLE      TargetProcessHandle,
	_Out_opt_ PHANDLE     TargetHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_      ULONG       HandleAttributes,
	_In_      ULONG       Options
)
{
	GET_SYSTEM_ROUTINE(NtDuplicateObject);
	return _NtDuplicateObject(
		SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAccess,
		HandleAttributes,
		Options
	);
}

NTSTATUS
NTAPI
NtQueryObject(
	_In_opt_  HANDLE	Handle,
	_In_      ULONG		ObjectInformationClass,
	_Out_opt_ PVOID		ObjectInformation,
	_In_      ULONG		ObjectInformationLength,
	_Out_opt_ PULONG	ReturnLength
)
{
	GET_SYSTEM_ROUTINE(NtQueryObject);
	return _NtQueryObject(
		Handle,
		ObjectInformationClass,
		ObjectInformation,
		ObjectInformationLength,
		ReturnLength
	);
}
NTSTATUS
NTAPI
NtCreateSection(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
)
{
	GET_SYSTEM_ROUTINE(NtCreateSection);
	return _NtCreateSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		MaximumSize,
		SectionPageProtection,
		AllocationAttributes,
		FileHandle
	);
}

NTSTATUS
NTAPI
NtMapViewOfSection(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID* BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
)
{
	GET_SYSTEM_ROUTINE(NtMapViewOfSection);
	return _NtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Win32Protect
	);
}
NTSTATUS
NTAPI
NtUnmapViewOfSection(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
)
{
	GET_SYSTEM_ROUTINE(NtUnmapViewOfSection);
	return _NtUnmapViewOfSection(
		ProcessHandle,
		BaseAddress
	);
}

NTSTATUS NTAPI NtCreateEvent(
	_Out_    PHANDLE            EventHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     EVENT_TYPE         EventType,
	_In_     BOOLEAN            InitialState
)
{
	GET_SYSTEM_ROUTINE(NtCreateEvent);
	return _NtCreateEvent(
		EventHandle,
		DesiredAccess,
		ObjectAttributes,
		EventType,
		InitialState
	);
}

NTSTATUS NTAPI NtQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
)
{
	GET_SYSTEM_ROUTINE(NtQueryInformationProcess);
	return _NtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength
	);
}

VOID NTAPI RtlInitUnicodeString(
	_Inout_  PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
)
{
	GET_SYSTEM_ROUTINE(RtlInitUnicodeString);
	return _RtlInitUnicodeString(
		DestinationString,
		SourceString
	);
}

VOID NTAPI RtlFreeUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString
)
{
	GET_SYSTEM_ROUTINE(RtlFreeUnicodeString);
	return _RtlFreeUnicodeString(
		UnicodeString
	);
}

ULONG NTAPI RtlNtStatusToDosError(
	_In_ NTSTATUS Status
)
{
	GET_SYSTEM_ROUTINE(RtlNtStatusToDosError);
	return _RtlNtStatusToDosError(
		Status
	);
}
NTSTATUS NTAPI RtlDosApplyFileIsolationRedirection_Ustr(
	IN ULONG Flags,
	IN PUNICODE_STRING OriginalName,
	IN PUNICODE_STRING Extension,
	IN OUT PUNICODE_STRING StaticString,
	IN OUT PUNICODE_STRING DynamicString,
	IN OUT PUNICODE_STRING* NewName,
	IN PULONG  NewFlags,
	IN PSIZE_T FileNameSize,
	IN PSIZE_T RequiredLength
)
{
	GET_SYSTEM_ROUTINE(RtlDosApplyFileIsolationRedirection_Ustr);
	return _RtlDosApplyFileIsolationRedirection_Ustr(
		Flags,
		OriginalName,
		Extension,
		StaticString,
		DynamicString,
		NewName,
		NewFlags,
		FileNameSize,
		RequiredLength
	);
}

ACCESS_MASK
QueryHandleAccessRights(
	HANDLE handle
)
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handle_info;
	ACCESS_MASK access_mask = 0;
	ULONG handle_info_size = 0x10000;
	ULONG pid;
	ULONG i;
	handle_info = (PSYSTEM_HANDLE_INFORMATION)malloc(handle_info_size);

	/*
		So this is kinda hacky, the operating system does not really effectively communicate with you as to what exactly went wrong here.
		It just kinda tells you that the memory buffer you sent is not corret and you just kinda have to hack your way
		to the correct buffer size.
	*/
	do
	{
		status = NtQuerySystemInformation(
			SystemHandleInformation,
			handle_info,
			handle_info_size,
			NULL
		);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			handle_info = (PSYSTEM_HANDLE_INFORMATION)realloc(handle_info, handle_info_size *= 2);
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status))
	{
		//FAIL
		free(handle_info);
		return EXIT_FAILURE;
	}
	pid = GetCurrentProcessId();

	for (i = 0; i < handle_info->HandleCount; i++)
	{
		SYSTEM_HANDLE sys_handle = handle_info->Handles[i];
		if (sys_handle.ProcessId != pid || (HANDLE)sys_handle.Handle != handle) {
			continue;
		}
		access_mask = sys_handle.GrantedAccess;
	}
	free(handle_info);
	return access_mask;
}