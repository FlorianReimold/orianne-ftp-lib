#include <orianne/ftp_server.h>

#include <iostream>

#ifndef ASIO_STANDALONE
using namespace boost;
#endif // ASIO_STANDALONE

int main() {
  try {
	asio::io_service io_service;

#ifdef WIN32
    orianne::FtpServer server(io_service, 21, "C:\\");
#else // WIN32
  orianne::FtpServer server(io_service, 21, "/");
#endif // WIN32

	io_service.run();
  }
  catch(std::exception& e)
  {
	std::cerr << e.what() << std::endl;
  }

  return 0;
}
