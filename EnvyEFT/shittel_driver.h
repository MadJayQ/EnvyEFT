#pragma once

#include "vuln_driver.h"
#include "shittel_driver_defs.h"

namespace kernel
{
	namespace intel
	{

		class intel_vulnerable_driver : public kernel::vulnerable_driver
		{
		public:
			intel_vulnerable_driver();
			// Inherited via vulnerable_driver
			virtual bool driver_read_primitive(uint64_t address, void* buffer, uint64_t buffer_size) override;
			virtual bool driver_write_primitive(uint64_t address, void* buffer, uint64_t buffer_size) override;
			virtual bool driver_force_write(uint64_t address, void* buffer, uint64_t buffer_size) override;

			virtual uint64_t allocate_kernel_pool(POOL_TYPE pool_type, uint64_t pool_size) override;
			virtual bool free_kernel_pool(uint64_t address) override;

		private:
			uint64_t intel_map_physical(uint64_t address, uint32_t size);
			bool intel_unmap_physical(uint64_t address, uint32_t size);
			uint64_t intel_rva_to_physical(uint64_t address);
			bool intel_copy_memory(uint64_t destination, uint64_t source, uint64_t size);
		};
	}
}