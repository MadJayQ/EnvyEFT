#pragma once

#include <stdint.h>

namespace binary
{
	class module
	{
	public:
		module(uint64_t handle);
		module() {}

		uint64_t get_module_handle() const { }

	};
}
