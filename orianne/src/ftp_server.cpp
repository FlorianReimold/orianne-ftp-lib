#include <orianne/ftp_server.h>
#include "ftp_console.h"
#include "ftp_session.h"
#include "filesystem.h"

#include <memory>
#include <iostream>

#ifndef ASIO_STANDALONE
using namespace boost;
using boost::system::error_code;
#else
using asio::error_code;
#endif // ASIO_STANDALONE

struct connection_handler : std::enable_shared_from_this<connection_handler> {

  explicit connection_handler(asio::io_service& service, std::string path)
    : socket(service), session(service, socket), console(session)
  {
    session.set_root_directory(path);
  }

  typedef std::shared_ptr<connection_handler> ptr;

  static ptr create(asio::io_service& service, std::string path) {
    return ptr(new connection_handler(service, path));
  }

  asio::ip::tcp::socket socket;
  orianne::FtpSession session;
  orianne::FtpConsole console;
  asio::streambuf buf;

  void handle_connect(const error_code code, orianne::FtpServer* server) {
#ifndef NDEBUG
    std::cout << "[FTP]: Client connected" << std::endl;
#endif

    console.set_write_callback(std::bind(&connection_handler::write_message,
      this, std::placeholders::_1));

    asio::async_write(socket,
      asio::buffer(console.greeter()),
      std::bind(&connection_handler::handle_write, shared_from_this(),
        /*asio::placeholders::error*/ std::placeholders::_1,
        /*asio::placeholders::bytes_transferred*/ std::placeholders::_2));

    trigger_read();

    server->start();
  }

  void trigger_read() {
    if (socket.is_open()) {
      asio::async_read_until(socket, buf, "\n",
        std::bind(&connection_handler::handle_read, shared_from_this()));
    }
  }

  void handle_write(const error_code& /*error*/, size_t
  /*bytes_transferred*/) {

  }

  void handle_read() {
    std::istream is(&buf);
    std::string s;
    getline(is, s);
    if (s.size() > 0) {
      console.read_line(s);

      trigger_read();
    }
  }

  void write_message(const std::string& message) {
    const char* buf = message.c_str();
    std::string *str = new std::string(buf);
    str->append("\r\n");
    //#ifndef NDEBUG
    //    std::cout << "[FTP] > " << *str << std::endl;
    //#endif
    asio::async_write(socket, asio::buffer(*str),
      std::bind(&connection_handler::dispose_write_buffer,
        shared_from_this(), /*asio::placeholders::error*/ std::placeholders::_1,
        /*asio::placeholders::bytes_transferred*/ std::placeholders::_2));
  }

  void dispose_write_buffer(const error_code& /*error*/,
    size_t /*bytes_transferred*/) {

  }
};

orianne::FtpServer::FtpServer(asio::io_service& io_service, uint16_t port, std::string path)
  : acceptor(io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
  , io_service_(io_service)
{
#ifdef WIN32
  char path_separator = '\\';
  bool windows_path = true;
#else
  char path_separator = '/';
  bool windows_path = false;
#endif // WIN32

  this->path = orianne::Filesystem::cleanPath(path, windows_path, path_separator);

#ifndef NDEBUG
  std::cout << "[FTP]: Starting FTP Server on port " << getPort() << " with local root \"" << this->path << "\"" << std::endl;
#endif

  start();
}

void orianne::FtpServer::start() {
  connection_handler::ptr handler = connection_handler::create(io_service_, path);
  std::shared_ptr<connection_handler>& sptr(handler);

  acceptor.async_accept(handler->socket,
    std::bind(&connection_handler::handle_connect, sptr,
      /*asio::placeholders::error*/ std::placeholders::_1, this));
}

uint16_t orianne::FtpServer::getPort() const
{
  return acceptor.local_endpoint().port();
}