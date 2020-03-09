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

	typedef struct _INTEL_IOTCL
	{
		uint64_t case_number;
	}INTEL_IOCTL, * PINTEL_IOCTL;

	INTEL_IOCTL_STRUCT(COPY_MEMORY_BUFFER_INFO) 
	{
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}INTEL_COPY_MEMORY_BUFFER_INFO, *PINTELCOPY_MEMORY_BUFFER_INFO;

	INTEL_IOCTL_STRUCT(FILL_MEMORY_BUFFER_INFO)
	{
		uint64_t _reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}INTEL_FILL_MEMORY_BUFFER_INFO, *PINTEL_FILL_MEMORY_BUFFER_INFO;

	INTEL_IOCTL_STRUCT(TRANSLATE_VIRTUAL_ADDRESS_INFO)
	{
		uint64_t reserved;
		uint64_t target_rva;
		uint64_t translated_physical;
	}INTEL_TRANSLATE_VIRTUAL_ADDRESS_INFO, *PINTEL_TRANSLATE_VIRTUAL_ADDRESS_INFO;

	INTEL_IOCTL_STRUCT(MAP_IO_SPACE_BUFFER_INFO)
	{
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}INTEL_MAP_IO_SPACE_BUFFER_INFO, * PINTEL_MAP_IO_SPACE_BUFFER_INFO;

	INTEL_IOCTL_STRUCT(UNMAP_IO_SPACE_BUFFER_INFO)
	{
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}INTEL_UNMAP_IO_SPACE_BUFFER_INFO, *PINTEL_UNMAP_IO_SPACE_BUFFER_INFO;


}