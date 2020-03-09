#pragma once

#include "ntdefs.h"


#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define GET_SYSTEM_ROUTINE(NAME) {\
						if(_##NAME == NULL)\
						{\
							_##NAME = (__##NAME)GetLibraryProcAdr("ntdll.dll", #NAME);\
						}\
}\


#define SystemHandleInformation 16
#define SystemModuleInformation 11
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2


/*
	This file defines all the functions that are available inside of NTDLL, they are all syscalls that point to kernel equivalents
	These are the API calls that we will use to interface with the Windows Kernel
*/
NTSTATUS NTAPI NtQuerySystemInformation(
	_In_      ULONG		SystemInformationClass,
	_Inout_   PVOID		SystemInformation,
	_In_      ULONG		SystemInformationLength,
	_Out_opt_ PULONG	ReturnLength
);
NTSTATUS NTAPI NtDuplicateObject(
	_In_      HANDLE      SourceProcessHandle,
	_In_      HANDLE      SourceHandle,
	_In_opt_  HANDLE      TargetProcessHandle,
	_Out_opt_ PHANDLE     TargetHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_      ULONG       HandleAttributes,
	_In_      ULONG       Options
);

NTSTATUS NTAPI NtQueryObject(
	_In_opt_  HANDLE	Handle,
	_In_      ULONG		ObjectInformationClass,
	_Out_opt_ PVOID		ObjectInformation,
	_In_      ULONG		ObjectInformationLength,
	_Out_opt_ PULONG	ReturnLength
);

NTSTATUS NTAPI NtCreateSection(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);
NTSTATUS NTAPI NtMapViewOfSection(
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
);
NTSTATUS NTAPI NtUnmapViewOfSection(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
);

NTSTATUS NTAPI NtCreateEvent(
	_Out_    PHANDLE            EventHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     EVENT_TYPE         EventType,
	_In_     BOOLEAN            InitialState
);

NTSTATUS NTAPI NtQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

VOID NTAPI RtlInitUnicodeString(
	_Inout_  PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
);

VOID NTAPI RtlFreeUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString
);

ULONG NTAPI RtlNtStatusToDosError(
	_In_ NTSTATUS Status
);

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
);


ACCESS_MASK QueryHandleAccessRights(HANDLE handle);