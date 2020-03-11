#pragma once

#include "ntdefs.h"

#include <string>

#include <memory>
#include <unordered_map>
#include <ostream>

#include "vuln_driver.h"

namespace kernel
{
	struct syscall_patch_context
	{
		uint64_t kernel_function_pointer = 0;
		//movabs rax, <kernel_function_pointer>
		uint8_t function_call_template[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint64_t kernel_original_function_address = 0;
		uint8_t kernel_original_function_jmp[sizeof(function_call_template)];
	};

	//Forward declaration
	class kernel_module;

	class kernel_module
	{
	public:
		kernel_module(const std::string& kernel);

		static kernel_module* get_kernel_module(const std::string& kernel);

		friend std::ostream& operator <<(std::ostream& os, const kernel_module& module);
		uint64_t get_module_export(vulnerable_driver* driver, const std::string& export_name);

		bool patch_syscall(vulnerable_driver* driver, uint64_t target_address);
		bool restore_syscall(vulnerable_driver* driver);

	private:
		uint64_t _base_address;
		uint64_t _image_size;
		uint64_t _image_mapped_base;

		std::string _module_name;

		syscall_patch_context* current_syscall_patch = nullptr;
	};

	//template<typename T, typename ...Args>
	//inline bool kernel_module::execute_and_restore_syscall(vulnerable_driver* driver, T* output_buffer, const Args ...args)
	//{

	//	constexpr auto call_void = std::is_same_v<T, void>;

	//	if constexpr (!call_void)
	//	{
	//		if (!output_buffer)
	//			return false;
	//	}
	//	else
	//	{
	//		UNREFERENCED_PARAMETER(output_buffer);
	//	}

	//	FARPROC usermode_addr = GetProcAddress(LoadLibrary("win32u.dll"), "NtGdiGetCOPPCompatibleOPMInformation");

	//	if (current_syscall_patch == nullptr)
	//	{
	//		throw "No valid syscall patch context set";
	//	}
	//	using FunctionFn = T(__stdcall*)(Args...);
	//	const auto fn = reinterpret_cast<FunctionFn>(usermode_addr);

	//	if constexpr (!call_void)
	//	{
	//		DebugBreak();
	//		*output_buffer = fn(args...);
	//	}
	//	else
	//	{
	//		fn(args...);
	//	}

	//	bool success = driver->driver_force_write(current_syscall_patch->kernel_function_pointer, current_syscall_patch->kernel_original_function_jmp, sizeof(current_syscall_patch->kernel_original_function_jmp));
	//	delete current_syscall_patch;

	//	return success;
	//}
}
