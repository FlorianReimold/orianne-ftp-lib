#include <orianne/ftp_server.h>

#include <iostream>

int main() {
  try {
	boost::asio::io_service io_service;
	orianne::FtpServer server(io_service, 8080, "D:\\meas");
	io_service.run();
  }
  catch(std::exception& e)
  {
	std::cerr << e.what() << std::endl;
  }
	
  return 0;
}
