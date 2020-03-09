#include "windows_service.h"

#include <filesystem>


using namespace kernel;


void windows_service::set_path(const std::string& path)
{
	_path = path;
	_driver_name = std::filesystem::path(path).filename().string();
}

kernel::windows_service::handle kernel::windows_service::system_service_manager()
{
	//Raise a GOTCHA so you don't forget to release this
	return OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
}

windows_service::windows_service(const std::string& path)
{
	set_path(path);
	if (!register_service())
		throw new windows_service_exception("failed to register service", 0);
	if (!start_service())
		throw new windows_service_exception("failed to create service", 0);
}

bool windows_service::register_service()
{
	handle service_manager = system_service_manager();
	if (!service_manager)
		return false;

	_service_handle = CreateService(service_manager, _driver_name.c_str(), _driver_name.c_str(), 
		SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER, 
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, _path.c_str(),
		nullptr, nullptr, nullptr, nullptr, nullptr);

	if (!_service_handle)
	{
		_service_handle = OpenService(service_manager, _driver_name.c_str(), SERVICE_START);

		if (_service_handle)
		{
			CloseServiceHandle(service_manager);
			return false;
		}
	}
	CloseServiceHandle(service_manager);

	return true;
	
}

bool windows_service::start_service()
{
	const bool res = StartService(_service_handle, 0, nullptr);
	//Raise GOTCHA so we remember to stop the service as to not leak our service handle
	return res;
}

bool windows_service::stop_service()
{
	const handle service_manager = system_service_manager();

	return false;
}

bool windows_service::delete_service()
{
	return false;
}





