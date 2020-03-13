#pragma once

#include "ntdefs.h"

#include <string>
#include <vector>

namespace kernel
{
	class windows_service_exception : public std::exception
	{
	protected:
		int _errno;
		std::string _error_msg;
	public:
		explicit windows_service_exception(const std::string& msg, int err) :
			_error_msg(msg),
			_errno(err)
		{}

		virtual ~windows_service_exception() throw () {}

		virtual const char* what() const throw() { return _error_msg.c_str(); }
		virtual int getErrorNumber() const throw() { return _errno; }
		//virtual int getErrorOffset() const throw() { return _error_offset; }
	};
	class windows_service
	{
		using handle = SC_HANDLE;
	public:
		windows_service(const std::string& driver_name);

		bool register_service();
		bool start_service();

		bool stop_service();

		void load_driver(const uint8_t* driver_bytes, size_t byte_size);

	private:

		static handle system_service_manager();
	private:
		std::string _path;
		std::string _driver_name;
		handle _service_handle;
		
	};
}