#pragma once

#ifdef ASIO_STANDALONE
#include <asio.hpp>
#else // ASIO_STANDALONE
#include <boost/asio.hpp>
using boost;
#endif // ASIO_STANDALONE

#include <string>

namespace orianne {

  class FtpServer {
  public:
    FtpServer(asio::io_service& io_service, uint16_t port, std::string path);
    void start();

    uint16_t getPort() const;

  private:
    std::string path;
    asio::ip::tcp::acceptor acceptor;
    asio::io_service& io_service_;
  };

}
