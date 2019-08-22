#include <orianne/ftp_server.h>

#include <iostream>

#ifndef ASIO_STANDALONE
using namespace boost;
#endif // ASIO_STANDALONE

int main() {
  try {
	asio::io_service io_service;

    uint16_t port = 2121;
#ifdef WIN32
    std::string local_root =  "C:\\"; // The backslash at the end is necessary!
#else // WIN32
    std::string local_root =  "/";
#endif // WIN32

    orianne::FtpServer server(io_service, port, local_root);

	io_service.run();
  }
  catch(std::exception& e)
  {
	std::cerr << e.what() << std::endl;
  }

  return 0;
}
