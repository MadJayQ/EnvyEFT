#include "windows_service.h"

#include <filesystem>
#include <array>
#include <fstream>

using namespace kernel;



windows_service::handle kernel::windows_service::system_service_manager()
{
	//Raise a GOTCHA so you don't forget to release this
	return OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
}

windows_service::windows_service(const std::string& driver_name)
{
	_path = "";
	_driver_name = driver_name;
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

	if (!service_manager)
		return false;

	const handle service_handle = OpenService(service_manager, _driver_name.c_str(), SERVICE_STOP | DELETE);

	if (!service_handle)
	{
		CloseServiceHandle(service_manager);
		return false;
	}

	SERVICE_STATUS status = { 0 };

	const bool result = ControlService(service_handle, SERVICE_CONTROL_STOP, &status) && DeleteService(service_handle);

	CloseHandle(service_handle);
	CloseHandle(service_manager);

	return result;
}

void windows_service::load_driver(const uint8_t* driver_bytes, size_t num_bytes)
{
	std::array<char, MAX_PATH> directory;
	directory.fill('\0');

	const uint32_t temp_path_result = GetTempPathA(sizeof(directory), directory.data());

	if (!temp_path_result || temp_path_result > MAX_PATH)
		throw new windows_service_exception("INVALID TEMP PATH", 0);

	const std::string driver_path = std::string(directory.data()) + "\\" + _driver_name;
	std::remove(driver_path.c_str());

	_path = driver_path;
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write((const char*)driver_bytes, num_bytes))
	{
		file_ofstream.close();
		throw new windows_service_exception("failed to write driver bytes", 0);
		return;
	}

	file_ofstream.close();
	if (!register_service())
		throw new windows_service_exception("failed to register service", 0);
	if (!start_service())
		throw new windows_service_exception("failed to create service", 0);
}





