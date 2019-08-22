#include "ftp_session.h"

#include <fstream>

#include "filesystem.h"

#ifdef WIN32
#include <direct.h>
#endif // WIN32

#include <memory>
#include <functional>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef WIN32
#include <dirent.h>
#endif // !WIN32


////////////////////////////////////////////////////////////////////////////////
/// Dumper Classes
////////////////////////////////////////////////////////////////////////////////

template<typename T> struct dumper : std::enable_shared_from_this<T> {
  asio::io_service& service;
  asio::ip::tcp::socket socket;
  std::function<void(const orianne::FtpResult&)> callback;

  explicit dumper(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service_)
    : service(service_), socket(service), callback(cb)
  {
  }

  static std::shared_ptr<T> create(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service) {
    return std::shared_ptr<T>(new T(cb, service));
  }

  void async_wait(asio::ip::tcp::acceptor& acceptor)
  {
    acceptor.async_accept(socket, std::bind(&T::handle_connect, this->shared_from_this()));
  }
};

struct DirListDumper : dumper<DirListDumper> {
  std::string data;

  explicit DirListDumper(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service)
    : dumper(cb, service)
  {
  }

  void handle_connect() {
    asio::async_write(socket,
      asio::buffer(data),
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
  asio::mutable_buffers_1 m_buffer;

  explicit FileDumper(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service, const std::string& path)
    : dumper(cb, service), stream(path.c_str(), std::ios::in | std::ios::binary), m_buffer(buffer, 1024)
  {
  }

  static std::shared_ptr<FileDumper> create(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service, const std::string& path) {
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
        m_buffer = asio::buffer(buffer, (size_t)count);

      asio::async_write(socket,
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

  explicit FileLoader(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service, const std::string& path)
    : dumper(cb, service), stream(path.c_str(), std::ios::out | std::ios::binary)
  {
  }

  static std::shared_ptr<FileLoader> create(std::function<void(const orianne::FtpResult&)> cb, asio::io_service& service, const std::string& path) {
    return std::shared_ptr<FileLoader>(new FileLoader(cb, service, path));
  }

  void handle_connect() {
    callback(orianne::FtpResult(150, "Receiving file contents."));

    asio::async_read(socket,
      asio::buffer(buffer, 4096),
      asio::transfer_at_least(1),
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
      asio::async_read(socket,
        asio::buffer(buffer, 4096),
        asio::transfer_all(),
        std::bind(static_cast<void(FileLoader::*)(size_t)>(&FileLoader::handle_read),
          shared_from_this(),
          std::placeholders::_2));
    }
  }

  ~FileLoader() {
  }
};

////////////////////////////////////////////////////////////////////////////////
/// Ftp Session
////////////////////////////////////////////////////////////////////////////////


orianne::FtpSession::FtpSession(asio::io_service& _service, asio::ip::tcp::socket& socket_)
  : io_service(_service), acceptor(0), ftp_working_directory("/"), socket(socket_)
{
}

void orianne::FtpSession::set_root_directory(const std::string& directory)
{
  local_filesystem_root = orianne::Filesystem::cleanPathNative(directory);
}

orianne::FtpResult orianne::FtpSession::set_username(const std::string& username)
{
  return orianne::FtpResult(331, "Please enter your password.");
}

orianne::FtpResult orianne::FtpSession::set_password(const std::string& password) {
  return orianne::FtpResult(230, "Login successful.");
}

static std::string endpoint_to_string(asio::ip::address_v4::bytes_type address, unsigned short port) {
  std::stringstream stream;
  stream << "(";
  for (int i = 0; i<4; i++)
    stream << (int)address[i] << ",";
  stream << ((port >> 8) & 0xff) << "," << (port & 0xff) << ")";

  return stream.str();
}

orianne::FtpResult orianne::FtpSession::set_passive() {
  if (acceptor == 0)
    acceptor = new asio::ip::tcp::acceptor(io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0)); // Port = 0 makes the OS choose a free port for us!

  std::string tmp_message = "Entering passive mode ";
  tmp_message.append(endpoint_to_string(socket.local_endpoint().address().to_v4().to_bytes(), acceptor->local_endpoint().port()));

  return orianne::FtpResult(227, tmp_message);
}

orianne::FtpResult orianne::FtpSession::get_size(const std::string& filename) {
  auto local_path = to_local_path(filename);

  Filesystem::FileStatus file_status(local_path);

  if (!file_status.isOk())
    return orianne::FtpResult(550, "Get Size Error: File does not exist or permission denied.");

  if (file_status.type() != Filesystem::FileType::RegularFile)
    return orianne::FtpResult(550, "Get Size Error: The resource is no regular file.");

  return orianne::FtpResult(213, std::to_string(file_status.fileSize()));
}

orianne::FtpResult orianne::FtpSession::change_working_directory(const std::string& new_directory) {

  if (new_directory.empty())
  {
    return orianne::FtpResult(550, "Failed ot change directory: Empty path");
  }

  std::string absolute_new_working_dir;

  if (new_directory[0] == '/')
  {
    // Absolute path given
    absolute_new_working_dir = orianne::Filesystem::cleanPath(new_directory, false, '/');
  }
  else
  {
    // Make the path abolute
    absolute_new_working_dir = orianne::Filesystem::cleanPath(ftp_working_directory + "/" + new_directory, false, '/');
  }

  auto local_path = to_local_path(absolute_new_working_dir);
  Filesystem::FileStatus file_status(local_path);

  if (!file_status.isOk())
    return orianne::FtpResult(550, "Failed ot change directory: The given resource does not exist or permission denied.");

  if (file_status.type() != Filesystem::FileType::Dir)
    return orianne::FtpResult(550, "Failed ot change directory: The given resource is not a directory.");

  if (!file_status.canOpenDir())
    return orianne::FtpResult(550, "Failed ot change directory: Permission denied.");

  ftp_working_directory = absolute_new_working_dir;
  return orianne::FtpResult(250, "OK");
}

orianne::FtpResult orianne::FtpSession::create_new_directory(const std::string& new_directory) {
  auto local_path = to_local_path(new_directory);

#ifdef WIN32
  int ret = _mkdir(local_path.c_str());
#else
  mode_t mode = 0755;
  int ret = mkdir(local_path.c_str(), mode);
#endif

  if (ret == 0)
  {
    return orianne::FtpResult(257, "OK");
  }
  else
  {
    return orianne::FtpResult(550, "Error creating directory.");
  }
}

orianne::FtpResult orianne::FtpSession::remove_directory(const std::string& directory) {
  auto local_path = to_local_path(directory);

#ifdef WIN32
  int ret = _rmdir(local_path.c_str());
#else
  mode_t mode = 0755;
  int ret = rmdir(local_path.c_str());
#endif

  if (ret == 0)
  {
    return orianne::FtpResult(257, "OK");
  }
  else
  {
    return orianne::FtpResult(550, "Error removing directory.");
  }
}

orianne::FtpResult orianne::FtpSession::remove_file(const std::string& filename)
{
  auto local_path = to_local_path(filename);

#ifdef WIN32
  int ret = _unlink(local_path.c_str());
#else
  mode_t mode = 0755;
  int ret = unlink(local_path.c_str());
#endif

  if (ret == 0)
  {
    return orianne::FtpResult(257, "OK");
  }
  else
  {
    return orianne::FtpResult(550, "Error removing file.");
  }
}

orianne::FtpResult orianne::FtpSession::rename_file_from(const std::string& from_path) {
  auto local_path = to_local_path(from_path);

  rename_from_path = local_path;

  return orianne::FtpResult(350, "Waiting for target path.");
}

orianne::FtpResult orianne::FtpSession::rename_file_to(const std::string& to_path) {
  if (rename_from_path.empty())
  {
    return orianne::FtpResult(503, "Use RNFR before RNTO.");
  }

  auto local_to_path = to_local_path(to_path);

  if (rename(rename_from_path.c_str(), local_to_path.c_str()) == 0)
  {
    rename_from_path.clear();
    return orianne::FtpResult(250, "OK");
  }
  else
  {
    rename_from_path.clear();
    return orianne::FtpResult(550, "Error renaming file.");
  }
}

orianne::FtpResult orianne::FtpSession::set_type(const struct orianne::FtpTransferType& type)
{
  return orianne::FtpResult(200, "Switching to Binary mode.");
}

orianne::FtpResult orianne::FtpSession::get_working_directory() {
  std::string pwd = ftp_working_directory;
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

static std::string get_list(const std::string& local_filesystem_path) {
  std::stringstream stream;

  orianne::Filesystem::FileStatus dir_status(local_filesystem_path);
  if (dir_status.type() != orianne::Filesystem::FileType::Dir)
    return ""; // TODO: return proper error code!

  auto dir_content = orianne::Filesystem::dirContent(local_filesystem_path);

  for (const auto& entry : dir_content)
  {
    const std::string& filename(entry.first);
    const orianne::Filesystem::FileStatus& file_status(entry.second);

    stream << ((file_status.type() == orianne::Filesystem::FileType::Dir) ? 'd' : '-') << file_status.permissionString() << "   1 ";
    stream << std::setw(10) << file_status.ownerString() << " " << std::setw(10) << file_status.groupString() << " ";
    stream << std::setw(10) << file_status.fileSize() << " ";
    stream << file_status.timeString() << " ";
    stream << filename;
    stream << "\r\n";
  }
  std::cout << "STR: \n" << stream.str() << std::endl;
  return stream.str();
}

void orianne::FtpSession::list(std::function<void(const orianne::FtpResult&)> cb) {
  std::shared_ptr<DirListDumper> dumper(new DirListDumper(cb, io_service));

  auto local_path = to_local_path(ftp_working_directory);

  dumper->set_data(get_list(local_path));
  dumper->async_wait(*acceptor);
}

void orianne::FtpSession::store(const std::string& filename, std::function<void(const orianne::FtpResult&)> cb) {
  auto local_path = to_local_path(filename);

  std::cout << "Opening " << local_path << " for upload" << std::endl;

  std::shared_ptr<FileLoader> dumper = FileLoader::create(cb, io_service, local_path);
  dumper->async_wait(*acceptor);
}

void orianne::FtpSession::retrieve(const std::string& filename, std::function<void(const orianne::FtpResult&)> cb) {
  auto local_path = to_local_path(filename);

  std::cout << "Opening " << local_path << " for download" << std::endl;

  std::shared_ptr<FileDumper> dumper = FileDumper::create(cb, io_service, local_path);
  dumper->async_wait(*acceptor);
}

orianne::FtpTransferType orianne::read_transfer_type(std::istream& stream) {
  orianne::FtpTransferType transfer_type;
  transfer_type.type = 'I';
  return transfer_type;
}

std::string orianne::FtpSession::to_local_path(const std::string& ftp_path)
{
  // First make the ftp path absolute if it isn't already
  std::string absolute_ftp_path;
  if (ftp_path[0] == '/')
  {
    absolute_ftp_path = ftp_path;
  }
  else
  {
    absolute_ftp_path = orianne::Filesystem::cleanPath(ftp_working_directory + "/" + ftp_path, false, '/');
  }

  // Now map it to the local filesystem
  return orianne::Filesystem::cleanPathNative(local_filesystem_root + "/" + absolute_ftp_path);
}
