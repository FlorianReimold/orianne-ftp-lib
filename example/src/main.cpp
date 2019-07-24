#include <orianne/ftp_server.h>

#include <iostream>

int main() {
  try {
	boost::asio::io_service io_service;

#ifdef WIN32
	orianne::FtpServer server(io_service, 8080, "D:\\meas");
#else // WIN32
  orianne::FtpServer server(io_service, 8080, "/");
#endif // WIN32

	io_service.run();
  }
  catch(std::exception& e)
  {
	std::cerr << e.what() << std::endl;
  }

  return 0;
}
