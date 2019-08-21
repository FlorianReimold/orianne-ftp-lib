#include <orianne/ftp_server.h>
#include "ftp_console.h"
#include "ftp_session.h"
#include "filesystem.h"

#include <memory>
#include <iostream>


orianne::FtpServer::FtpServer(boost::asio::io_service& io_service, uint16_t port, std::string path)
  : acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) {

#ifdef WIN32
  char path_separator = '\\';
  bool windows_path = true;
#else
  char path_separator = '/';
  bool windows_path = false;
#endif // WIN32

  this->path = orianne::Filesystem::cleanPath(path, windows_path, path_separator);
  start();
}

struct connection_handler : std::enable_shared_from_this<connection_handler> {

  explicit connection_handler(boost::asio::io_service& service, std::string path)
    : socket(service), session(service, socket), console(session)
  {
    session.set_root_directory(path);
  }

  typedef std::shared_ptr<connection_handler> ptr;

  static ptr create(boost::asio::io_service& service, std::string path) {
    return ptr(new connection_handler(service, path));
  }

  boost::asio::ip::tcp::socket socket;
  orianne::FtpSession session;
  orianne::FtpConsole console;
  boost::asio::streambuf buf;

  void handle_connect(const boost::system::error_code code, orianne::FtpServer* server) {
    std::cout << "handle_connection()" << std::endl;

    console.set_write_callback(std::bind(&connection_handler::write_message,
      this, std::placeholders::_1));

    boost::asio::async_write(socket,
      boost::asio::buffer(console.greeter()),
      std::bind(&connection_handler::handle_write, shared_from_this(),
        /*boost::asio::placeholders::error*/ std::placeholders::_1,
        /*boost::asio::placeholders::bytes_transferred*/ std::placeholders::_2));

    trigger_read();

    server->start();
  }

  void trigger_read() {
    if (socket.is_open()) {
      boost::asio::async_read_until(socket, buf, "\n",
        std::bind(&connection_handler::handle_read, shared_from_this()));
    }
  }

  void handle_write(const boost::system::error_code& /*error*/, size_t
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
    std::cout << "Message: " << *str << std::endl;
    boost::asio::async_write(socket, boost::asio::buffer(*str),
      std::bind(&connection_handler::dispose_write_buffer,
        shared_from_this(), /*boost::asio::placeholders::error*/ std::placeholders::_1,
        /*boost::asio::placeholders::bytes_transferred*/ std::placeholders::_2));
  }

  void dispose_write_buffer(const boost::system::error_code& /*error*/,
    size_t /*bytes_transferred*/) {

  }
};

void orianne::FtpServer::start() {
  std::cout << "start()" << std::endl;

  connection_handler::ptr handler =
    connection_handler::create(acceptor.get_io_service(), path);
  std::shared_ptr<connection_handler>& sptr(handler);

  acceptor.async_accept(handler->socket,
    std::bind(&connection_handler::handle_connect, sptr,
      /*boost::asio::placeholders::error*/ std::placeholders::_1, this));
}
