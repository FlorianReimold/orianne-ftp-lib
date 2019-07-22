#include "ftp_session.h"

#include <fstream>

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <direct.h>

#include <memory>
#include <functional>
#include <iostream>


template<typename T> struct dumper : std::enable_shared_from_this<T> {
  boost::asio::io_service& service;
  boost::asio::ip::tcp::socket socket;
  std::function<void(const orianne::FtpResult&)> callback;

  explicit dumper(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service_)
    : service(service_), socket(service), callback(cb)
  {
  }

  static std::shared_ptr<T> create(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service) {
    return std::shared_ptr<T>(new T(cb, service));
  }

  void async_wait(boost::asio::ip::tcp::acceptor& acceptor)
  {
    acceptor.async_accept(socket, std::bind(&T::handle_connect, this->shared_from_this()));
  }
};

struct DirListDumper : dumper<DirListDumper> {
  std::string data;

  explicit DirListDumper(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service)
    : dumper(cb, service)
  {
  }

  void handle_connect() {
    boost::asio::async_write(socket,
      boost::asio::buffer(data),
      std::bind(&DirListDumper::handle_write, shared_from_this()));
    callback(orianne::FtpResult(150, "Sending directory listing."));
  }

  void handle_write() {
    callback(orianne::FtpResult(226, "Done."));
  }

  void set_data(const std::string& data_) {
    data = data_;
  }
};

struct FileDumper : dumper<FileDumper> {
  std::ifstream stream;
  char buffer[1024];
  boost::asio::mutable_buffers_1 m_buffer;

  explicit FileDumper(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service, const std::string& path)
    : dumper(cb, service), stream(path.c_str(), std::ios::in | std::ios::binary), m_buffer(buffer, 1024)
  {
  }

  static std::shared_ptr<FileDumper> create(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service, const std::string& path) {
    return std::shared_ptr<FileDumper>(new FileDumper(cb, service, path));
  }

  void handle_connect() {
    callback(orianne::FtpResult(150, "Sending file contents."));

    handle_write();
  }

  void handle_write() {
    stream.read(buffer, 1024);
    std::streamsize count = stream.gcount();

    if (count == 0) {
      callback(orianne::FtpResult(226, "Done."));
    }
    else {
      if (count < 1024)
        m_buffer = boost::asio::buffer(buffer, (size_t)count);

      boost::asio::async_write(socket,
        m_buffer,
        std::bind(&FileDumper::handle_write, shared_from_this()));
    }
  }

  ~FileDumper() {
  }
};

struct FileLoader : dumper<FileLoader> {
  std::ofstream stream;
  char buffer[4096];

  explicit FileLoader(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service, const std::string& path)
    : dumper(cb, service), stream(path.c_str(), std::ios::out | std::ios::binary)
  {
  }

  static std::shared_ptr<FileLoader> create(std::function<void(const orianne::FtpResult&)> cb, boost::asio::io_service& service, const std::string& path) {
    return std::shared_ptr<FileLoader>(new FileLoader(cb, service, path));
  }

  void handle_connect() {
    callback(orianne::FtpResult(150, "Receiving file contents."));

    boost::asio::async_read(socket,
      boost::asio::buffer(buffer, 4096),
      boost::asio::transfer_at_least(1),
      std::bind(static_cast<void(FileLoader::*)(size_t)>(&FileLoader::handle_read),
        shared_from_this(),
        std::placeholders::_2));
  }

  void handle_read(std::size_t recvlen) {
    size_t count = recvlen;
    //std::cout << "buffer size: " << count << std::endl;

    if (count == 0) {
      callback(orianne::FtpResult(226, "Done."));
    }
    else {
      stream.write(buffer, count);
      buffer[0] = '\0';
      boost::asio::async_read(socket,
        boost::asio::buffer(buffer, 4096),
        boost::asio::transfer_all(),
        std::bind(static_cast<void(FileLoader::*)(size_t)>(&FileLoader::handle_read),
          shared_from_this(),
          std::placeholders::_2));
    }
  }

  ~FileLoader() {
  }
};




orianne::FtpSession::FtpSession(boost::asio::io_service& _service, boost::asio::ip::tcp::socket& socket_)
  : io_service(_service), acceptor(0), working_directory("/"), socket(socket_)
{
}

void orianne::FtpSession::set_root_directory(boost::filesystem::path const& directory) {
  root_directory = directory;
}

orianne::FtpResult orianne::FtpSession::set_username(const std::string& username) {
  return orianne::FtpResult(331, "Please enter your password.");
}

orianne::FtpResult orianne::FtpSession::set_password(const std::string& username) {
  return orianne::FtpResult(230, "Login successful.");
}

static std::string endpoint_to_string(boost::asio::ip::address_v4::bytes_type address, unsigned short port) {
  std::stringstream stream;
  stream << "(";
  for (int i = 0; i<4; i++)
    stream << (int)address[i] << ",";
  stream << ((port >> 8) & 0xff) << "," << (port & 0xff) << ")";

  return stream.str();
}

orianne::FtpResult orianne::FtpSession::set_passive() {
  if (acceptor == 0)
    acceptor = new boost::asio::ip::tcp::acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0)); // Port = 0 makes the OS choose a free port for us!

  std::string tmp_message = "Entering passive mode ";
  tmp_message.append(endpoint_to_string(socket.local_endpoint().address().to_v4().to_bytes(), acceptor->local_endpoint().port()));

  return orianne::FtpResult(227, tmp_message);
}

orianne::FtpResult orianne::FtpSession::get_size(const std::string& filename) {
  auto local_path = to_local_path(filename);

  if (!boost::filesystem::is_regular_file(local_path))
    return orianne::FtpResult(550, "Get Size Error: The resource is no regular file.");

  std::stringstream stream;
  stream << boost::filesystem::file_size(local_path);
  return orianne::FtpResult(213, stream.str());
}

orianne::FtpResult orianne::FtpSession::change_working_directory(const std::string& new_directory) {
  boost::filesystem::path actual_new_working_dir;

  if (new_directory[0] != '/') {
    if (new_directory.compare("..") == 0) {
      actual_new_working_dir = working_directory.parent_path();
    }
    else {
      actual_new_working_dir = working_directory / boost::filesystem::path(new_directory);
    }
  }
  else {
    std::string s = "/..";
    if (new_directory == s) {
      actual_new_working_dir = working_directory.parent_path();
    }
    else {
      actual_new_working_dir.assign(new_directory, boost::filesystem::path::codecvt());
    }
  }

  if (boost::filesystem::is_directory(root_directory / actual_new_working_dir))
  {
    working_directory = actual_new_working_dir;
    return orianne::FtpResult(250, "OK");
  }
  else
  {
    return orianne::FtpResult(550, "Failed to change directory");
  }

}

orianne::FtpResult orianne::FtpSession::create_new_directory(const std::string& new_directory) {
  auto local_path = to_local_path(new_directory);

  if (boost::filesystem::create_directory(local_path))
  {
    return orianne::FtpResult(257, "\"" + local_path.string() + "\"");
  }
  else
  {
    return orianne::FtpResult(550, "Error creating directory.");
  }
}

orianne::FtpResult orianne::FtpSession::remove_directory(const std::string& directory) {
  boost::filesystem::path local_path = to_local_path(directory);

  if (!boost::filesystem::is_directory(local_path))
  {
    return orianne::FtpResult(550, "Error removing directory. The given resource is not a directory.");
  }

  if (boost::filesystem::remove(local_path))
  {
    return orianne::FtpResult(250, "OK");
  }
  else
  {
    return orianne::FtpResult(550, "Error removing directory.");
  }
}

orianne::FtpResult orianne::FtpSession::remove_file(const std::string& filename)
{
  boost::filesystem::path local_path = to_local_path(filename);

  if (boost::filesystem::is_directory(local_path))
  {
    return orianne::FtpResult(550, "Error removing file. The resource is a directory.");
  }

  if (boost::filesystem::remove(local_path))
  {
    return orianne::FtpResult(250, "OK");
  }
  else
  {
    return orianne::FtpResult(550, "Error removing file.");
  }
}

orianne::FtpResult orianne::FtpSession::rename_file_from(const std::string& from_path) {
  auto local_path = to_local_path(from_path);

  rename_from_path = local_path.string();

  return orianne::FtpResult(350, "Waiting for target path.");
}

orianne::FtpResult orianne::FtpSession::rename_file_to(const std::string& to_path) {
  if (rename_from_path.empty()) {
    return orianne::FtpResult(503, "Use RNFR before RNTO.");
  }

  auto local_to_path = to_local_path(to_path);

  if (rename(rename_from_path.c_str(), local_to_path.string().c_str()) == 0) {
    return orianne::FtpResult(250, "OK");
  }
  else {
    return orianne::FtpResult(550, "Error renaming file.");
  }
}

orianne::FtpResult orianne::FtpSession::set_type(const struct orianne::FtpTransferType& type) {
  return orianne::FtpResult(200, "Switching to Binary mode.");
}

orianne::FtpResult orianne::FtpSession::get_working_directory() {
  std::string pwd = working_directory.string();
#ifdef WIN32
  std::replace(pwd.begin(), pwd.end(), '\\', '/'); // replace Windows separators by unix separators
#endif
  return orianne::FtpResult(257, "\"" + pwd + "\"");
}

orianne::FtpResult orianne::FtpSession::get_system() {
#if defined _WIN32 || defined _WIN64
  return orianne::FtpResult(215, "WIN32");
#elif __ANDROID__ 
  return orianne::FtpResult(215, "LINUX");
#elif __linux__ 
  return orianne::FtpResult(215, "LINUX");
#elif __APPLE__ && __MACH__
  return orianne::FtpResult(215, "MACOS");
#elif __FreeBSD__
  return orianne::FtpResult(215, "FREEBSD");
#elif __NetBSD__
  return orianne::FtpResult(215, "NETBSD");
#elif __OpenBSD__
  return orianne::FtpResult(215, "OPENBSD");
#else
  return orianne::FtpResult(215, "UNKNOWN");
#endif
}

static std::string get_list(const boost::filesystem::path& path) {
  std::stringstream stream;

  if (!boost::filesystem::is_directory(path))
    return "";

  for (boost::filesystem::directory_iterator it(path); it != boost::filesystem::directory_iterator(); it++) {
    struct stat t_stat;
    stat(it->path().string().c_str(), &t_stat);
    struct tm* timeinfo = localtime(&t_stat.st_ctime);
    char date[80];
    strftime(date, sizeof(date), "%b %e %Y", timeinfo);

    bool dir = boost::filesystem::is_directory(it->path());
    stream << boost::format("%crw-rw-rw-   1 %-10s %-10s %10lu %s %s\r\n")
      % (dir ? 'd' : '-')
      % "Orianne" % "Orianne"
      % (dir ? 0 : file_size(it->path()))
      % date
      % it->path().filename().string();
  }
  std::cout << "STR: \n" << stream.str() << std::endl;
  return stream.str();
}

void orianne::FtpSession::list(std::function<void(const orianne::FtpResult&)> cb) {
  std::shared_ptr<DirListDumper> dumper(new DirListDumper(cb, io_service));
  dumper->set_data(get_list(root_directory / working_directory));
  dumper->async_wait(*acceptor);
}

void orianne::FtpSession::store(const std::string& filename, std::function<void(const orianne::FtpResult&)> cb) {
  boost::filesystem::path path = root_directory / working_directory / filename;

  std::cout << "Opening " << path.make_preferred() << " for upload" << std::endl;

  std::shared_ptr<FileLoader> dumper = FileLoader::create(cb, io_service, path.make_preferred().string());
  dumper->async_wait(*acceptor);
}

void orianne::FtpSession::retrieve(const std::string& filename, std::function<void(const orianne::FtpResult&)> cb) {
  boost::filesystem::path path = root_directory / working_directory / filename;

  std::cout << "Opening " << path.make_preferred() << " for download" << std::endl;

  std::shared_ptr<FileDumper> dumper = FileDumper::create(cb, io_service, path.make_preferred().string());
  dumper->async_wait(*acceptor);
}

orianne::FtpTransferType orianne::read_transfer_type(std::istream& stream) {
  orianne::FtpTransferType transfer_type;
  transfer_type.type = 'I';
  return transfer_type;
}

boost::filesystem::path orianne::FtpSession::to_local_path(const std::string& ftp_path)
{
  boost::filesystem::path local_path;
  if (ftp_path[0] == '/')
  {
    // Absolute path
    local_path = root_directory / boost::filesystem::path(ftp_path);
  }
  else
  {
    // relative path
    local_path = root_directory / working_directory / boost::filesystem::path(ftp_path);
  }

  return local_path;
}