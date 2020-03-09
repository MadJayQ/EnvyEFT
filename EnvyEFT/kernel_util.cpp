#include "kernel_util.h"

using namespace kernel;

bool patch_vulnerable_syscall(uint64_t target_function_address)
{
	return false;
}

template<typename T, typename ...Args> bool dispatch_and_restore_syscall(const Args ...args)
{

}

