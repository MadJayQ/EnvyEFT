#pragma once


#include "ntdefs.h"
#include <iostream>


namespace kernel
{
	//Exploit behavior forward declaration
	class vulnerable_driver
	{
	public:
		vulnerable_driver(const std::string& driver_handle);

		virtual bool driver_read_primitive(uint64_t address, void* buffer, uint64_t buffer_size) = 0;
		virtual bool driver_write_primitive(uint64_t address, void* buffer, uint64_t buffer_size) = 0;

		virtual bool driver_force_write(uint64_t address, void* buffer, uint64_t buffer_size) = 0;

		virtual uint64_t allocate_kernel_pool(POOL_TYPE pool_type, uint64_t pool_size) = 0;
		virtual bool free_kernel_pool(uint64_t address) = 0;

	protected:
		HANDLE driver_handle;
		
	};
}
