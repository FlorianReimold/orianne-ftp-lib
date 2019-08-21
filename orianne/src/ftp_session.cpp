#include "ftp_session.h"

#include <fstream>

#include <boost/filesystem.hpp>

#ifdef WIN32
#include <direct.h>
#endif // WIN32

#include <memory>
#include <functional>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef WIN32
#include <dirent.h>
#endif // !WIN32


////////////////////////////////////////////////////////////////////////////////
/// Dumper Classes
////////////////////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////////////////////
/// Filesystem
////////////////////////////////////////////////////////////////////////////////

namespace Filesystem
{
  enum class FileType
  {
    Unknown,
    RegularFile,
    Dir,
    CharacterDevice,
    BlockDevice,
    Fifo,
    SymbolicLink,
    Socket
  };

  class FileStatus
  {
  public:
    FileStatus(const std::string& path)
      : path_(path)
    {
#ifdef WIN32
      const int error_code = _stat64(path.c_str(), &file_status_);
#else // WIN32
      const int error_code = stat(path.c_str(), &file_status_);
#endif // WIN32
      is_ok_ = (error_code == 0);
    }

    bool isOk() const
    {
      return is_ok_;
    }

    FileType type() const
    {
      if (!is_ok_)
        return FileType::Unknown;

      switch (file_status_.st_mode & S_IFMT) {
      case S_IFREG:  return FileType::RegularFile;
      case S_IFDIR:  return FileType::Dir;
      case S_IFCHR:  return FileType::CharacterDevice;
#ifndef WIN32
      case S_IFBLK:  return FileType::BlockDevice;
      case S_IFIFO:  return FileType::Fifo;
      case S_IFLNK:  return FileType::SymbolicLink;
      case S_IFSOCK: return FileType::Socket;
#endif // !WIN32
      default:       return FileType::Unknown;
      }

    }

    int64_t fileSize() const
    {
      if (!is_ok_)
        return 0;

      return file_status_.st_size;
    }

#ifdef WIN32
    bool permissionRootRead()     const { return 0 != (file_status_.st_mode & S_IREAD); }
    bool permissionRootWrite()    const { return 0 != (file_status_.st_mode & S_IWRITE); }
    bool permissionRootExecute()  const { return 0 != (file_status_.st_mode & S_IEXEC); }
    bool permissionGroupRead()    const { return 0 != (file_status_.st_mode & S_IREAD); }
    bool permissionGroupWrite()   const { return 0 != (file_status_.st_mode & S_IWRITE); }
    bool permissionGroupExecute() const { return 0 != (file_status_.st_mode & S_IEXEC); }
    bool permissionOwnerRead()    const { return 0 != (file_status_.st_mode & S_IREAD); }
    bool permissionOwnerWrite()   const { return 0 != (file_status_.st_mode & S_IWRITE); }
    bool permissionOwnerExecute() const { return 0 != (file_status_.st_mode & S_IEXEC); }
#else // WIN32
    bool permissionRootRead()     const { return 0 != (file_status_.st_mode & S_IRUSR); }
    bool permissionRootWrite()    const { return 0 != (file_status_.st_mode & S_IWUSR); }
    bool permissionRootExecute()  const { return 0 != (file_status_.st_mode & S_IXUSR); }
    bool permissionGroupRead()    const { return 0 != (file_status_.st_mode & S_IRGRP); }
    bool permissionGroupWrite()   const { return 0 != (file_status_.st_mode & S_IWGRP); }
    bool permissionGroupExecute() const { return 0 != (file_status_.st_mode & S_IXGRP); }
    bool permissionOwnerRead()    const { return 0 != (file_status_.st_mode & S_IROTH); }
    bool permissionOwnerWrite()   const { return 0 != (file_status_.st_mode & S_IWOTH); }
    bool permissionOwnerExecute() const { return 0 != (file_status_.st_mode & S_IXOTH); }
#endif // WIN32


    std::string permissionString() const
    {
      std::string permission_string(9, '-');

      if (!is_ok_)
        return permission_string;

#ifdef WIN32
      // Root
      permission_string[0] = (file_status_.st_mode & S_IREAD)  ? 'r' : '-';
      permission_string[1] = (file_status_.st_mode & S_IWRITE) ? 'w' : '-';
      permission_string[2] = (file_status_.st_mode & S_IEXEC)  ? 'x' : '-';
      // Group
      permission_string[3] = (file_status_.st_mode & S_IREAD)  ? 'r' : '-';
      permission_string[4] = (file_status_.st_mode & S_IWRITE) ? 'w' : '-';
      permission_string[5] = (file_status_.st_mode & S_IEXEC)  ? 'x' : '-';
      // Owner
      permission_string[6] = (file_status_.st_mode & S_IREAD)  ? 'r' : '-';
      permission_string[7] = (file_status_.st_mode & S_IWRITE) ? 'w' : '-';
      permission_string[8] = (file_status_.st_mode & S_IEXEC)  ? 'x' : '-';
#else // WIN32
      // Root
      permission_string[0] = (file_status_.st_mode & S_IRUSR) ? 'r' : '-';
      permission_string[1] = (file_status_.st_mode & S_IWUSR) ? 'w' : '-';
      permission_string[2] = (file_status_.st_mode & S_IXUSR) ? 'x' : '-';
      // Group
      permission_string[3] = (file_status_.st_mode & S_IRGRP) ? 'r' : '-';
      permission_string[4] = (file_status_.st_mode & S_IWGRP) ? 'w' : '-';
      permission_string[5] = (file_status_.st_mode & S_IXGRP) ? 'x' : '-';
      // Owner
      permission_string[6] = (file_status_.st_mode & S_IROTH) ? 'r' : '-';
      permission_string[7] = (file_status_.st_mode & S_IWOTH) ? 'w' : '-';
      permission_string[8] = (file_status_.st_mode & S_IXOTH) ? 'x' : '-';
#endif // WIN32
      return permission_string;
    }

    std::string ownerString() const
    {
      return "Orianne";
    }

    std::string groupString() const
    {
      return "Orianne";
    }

    std::string timeString() const
    {
      if (!is_ok_)
        return "Jan  1 1970";

      // The FTP Time format can be:
      // 
      //     MMM DD hh:mm
      //   OR
      //     MMM DD  YYYY
      //   OR
      //     MMM DD YYYY
      //
      // This means, that we can only return the time for files with the same
      // year as the current year.
      // 
      // https://files.stairways.com/other/ftp-list-specs-info.txt
      
      auto now = std::chrono::system_clock::now();
      time_t now_time_t = std::chrono::system_clock::to_time_t(now);
      struct tm* now_timeinfo = localtime(&now_time_t);
      int current_year = now_timeinfo->tm_year;

      struct tm* file_timeinfo = localtime(&file_status_.st_ctime);
      int file_year = file_timeinfo->tm_year;

      // Hardcoded english month names, because returning a localized string by strftime here may break certain FTP clients
      static std::string month_names[] =
      {
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec"
      };

      // Use strftime for the day and year / time
      char date[80];
      if (file_year == current_year)
      {
        // We are allowed to return the time!
        strftime(date, sizeof(date), " %e %R", file_timeinfo);
      }
      else
      {
        // We must not return the time, only the date :(
        strftime(date, sizeof(date), " %e  %Y", file_timeinfo);
      }

      return month_names[file_timeinfo->tm_mon] + std::string(date);
    }

    bool canOpenDir() const
    {
      if (!is_ok_)
        return false;

      if (type() != FileType::Dir)
        return false;

      bool can_open_dir(false);
#ifdef WIN32
      std::string find_file_path = path_ + "\\*";
      std::replace(find_file_path.begin(), find_file_path.end(), '/', '\\');

      HANDLE hFind;
      WIN32_FIND_DATAA ffd;
      hFind = FindFirstFileA(find_file_path.c_str(), &ffd);
      if (hFind != INVALID_HANDLE_VALUE)
      {
        can_open_dir = true;
      }
      FindClose(hFind);
#else // WIN32
      DIR *dp;
      struct dirent *dirp;
      if ((dp = opendir(path_.c_str())) != NULL)
      {
        can_open_dir = true;
      }
      closedir(dp);
#endif // WIN32

      return can_open_dir;
    }

    ~FileStatus() {}

  private:
    std::string path_;
    bool is_ok_;
#ifdef WIN32
    struct __stat64 file_status_;
#else // WIN32
    struct stat file_status_;
#endif 
  };

  std::map<std::string, FileStatus> dirContent(const std::string& path)
  {
    std::map<std::string, FileStatus> content;
#ifdef WIN32
    std::string find_file_path = path + "\\*";
    std::replace(find_file_path.begin(), find_file_path.end(), '/', '\\');

    HANDLE hFind;
    WIN32_FIND_DATAA ffd;
    hFind = FindFirstFileA(find_file_path.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
      std::cerr << "FindFirstFile Error" << std::endl;
      return content;
    }

    do
    {
      std::string file_name(ffd.cFileName);
      content.emplace(std::string(ffd.cFileName), FileStatus(path + "\\" + std::string(ffd.cFileName)));
    } while (FindNextFileA(hFind, &ffd) != 0);
    FindClose(hFind);
#else // WIN32
    DIR *dp;
    struct dirent *dirp;
    if((dp = opendir(path.c_str())) == NULL)
    {
        std::cerr << "Error opening directory: " << strerror(errno) << std::endl;
        return content;
    }

    while ((dirp = readdir(dp)) != NULL)
    {
      content.emplace(std::string(dirp->d_name), FileStatus(path + "/" + std::string(dirp->d_name)));
    }
    closedir(dp);

#endif // WIN32
    return content;
  }
}

////////////////////////////////////////////////////////////////////////////////
/// Ftp Session
////////////////////////////////////////////////////////////////////////////////


orianne::FtpSession::FtpSession(boost::asio::io_service& _service, boost::asio::ip::tcp::socket& socket_)
  : io_service(_service), acceptor(0), working_directory("/"), socket(socket_)
{
}

void orianne::FtpSession::set_root_directory(boost::filesystem::path const& directory)
{
  root_directory = directory;
}

orianne::FtpResult orianne::FtpSession::set_username(const std::string& username)
{
  return orianne::FtpResult(331, "Please enter your password.");
}

orianne::FtpResult orianne::FtpSession::set_password(const std::string& password) {
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

  Filesystem::FileStatus file_status(local_path.string());

  if (!file_status.isOk())
    return orianne::FtpResult(550, "Get Size Error: File does not exist or permission denied.");

  if (file_status.type() != Filesystem::FileType::RegularFile)
    return orianne::FtpResult(550, "Get Size Error: The resource is no regular file.");

  return orianne::FtpResult(213, std::to_string(file_status.fileSize()));
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

  auto local_path = to_local_path(actual_new_working_dir.string());
  Filesystem::FileStatus file_status(local_path.string());

  if (!file_status.isOk())
    return orianne::FtpResult(550, "Failed ot change directory: The given resource does not exist or permission denied.");

  if (file_status.type() != Filesystem::FileType::Dir)
    return orianne::FtpResult(550, "Failed ot change directory: The given resource is not a directory.");

  if (!file_status.canOpenDir())
    return orianne::FtpResult(550, "Failed ot change directory: Permission denied.");

  working_directory = actual_new_working_dir;
  return orianne::FtpResult(250, "OK");
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
  if (rename_from_path.empty())
  {
    return orianne::FtpResult(503, "Use RNFR before RNTO.");
  }

  auto local_to_path = to_local_path(to_path);

  if (rename(rename_from_path.c_str(), local_to_path.string().c_str()) == 0)
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

  Filesystem::FileStatus dir_status(path.string());
  if (dir_status.type() != Filesystem::FileType::Dir)
    return ""; // TODO: return proper error code!

  auto dir_content = Filesystem::dirContent(path.string());

  for (const auto& entry : dir_content)
  {
    const std::string& filename(entry.first);
    const Filesystem::FileStatus& file_status(entry.second);

    stream << ((file_status.type() == Filesystem::FileType::Dir) ? 'd' : '-') << file_status.permissionString() << "   1 ";
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
  dumper->set_data(get_list(root_directory / working_directory));
  dumper->async_wait(*acceptor);
}

void orianne::FtpSession::store(const std::string& filename, std::function<void(const orianne::FtpResult&)> cb) {
  boost::filesystem::path local_path = to_local_path(filename);

  std::cout << "Opening " << local_path.make_preferred() << " for upload" << std::endl;

  std::shared_ptr<FileLoader> dumper = FileLoader::create(cb, io_service, local_path.make_preferred().string());
  dumper->async_wait(*acceptor);
}

void orianne::FtpSession::retrieve(const std::string& filename, std::function<void(const orianne::FtpResult&)> cb) {
  boost::filesystem::path local_path = to_local_path(filename);

  std::cout << "Opening " << local_path.make_preferred() << " for download" << std::endl;

  std::shared_ptr<FileDumper> dumper = FileDumper::create(cb, io_service, local_path.make_preferred().string());
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
