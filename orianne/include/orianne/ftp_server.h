#pragma once

#include <boost/asio.hpp>
#include <string>

namespace orianne {
	
	class FtpServer {
	public:
		FtpServer(boost::asio::io_service& io_service, int port, std::string path);
		void start();
		
	private:
		std::string path;
		boost::asio::ip::tcp::acceptor acceptor;
	};
	
}
