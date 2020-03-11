#pragma once

#define INTEL_IOCTL_STRUCT(name) typedef struct _##name## : public _INTEL_IOTCL

namespace kernel::intel
{
	constexpr const char* driver_device_name = "\\\\.\\Nal";

	namespace ioctl
	{
		constexpr int TARGET_ICTL = 0x80862007;
	}

	namespace instruction_case_number
	{
		constexpr int COPY_MEMORY_BUFFER_INFO = 0x33; //This calls memcpy in the intel driver
		constexpr int FILL_MEMORY_BUFFER_INFO = 0x30; //This calls memset in the intel driver
		constexpr int TRANSLATE_RVA_TO_PHYSICAL = 0x25;
		constexpr int MAP_PHYSICAL_ADDRESS = 0x19;
		constexpr int UNMAP_PHYSICAL_ADDRESS = 0x1A;
	}

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;


}