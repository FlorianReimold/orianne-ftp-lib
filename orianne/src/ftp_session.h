#pragma once

#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include <functional>

namespace orianne {

  struct FtpTransferType {
    unsigned char type;
    unsigned char format;
    unsigned byte_size;
  };

  FtpTransferType read_transfer_type(std::istream& stream);

  struct FtpResult {
    FtpResult() {
    }

    FtpResult(unsigned code_, const std::string& message_)
      : code(code_), message(message_) {
    }

    unsigned code;
    std::string message;
  };



  //////////////////////////////////////////////////////////////////////////////
  /// Ftp Session
  //////////////////////////////////////////////////////////////////////////////

  class FtpSession {

  //////////////////////////////////
  /// Member variables
  //////////////////////////////////
  private:
    boost::asio::io_service& io_service;
    boost::asio::ip::tcp::acceptor* acceptor;
    boost::asio::ip::tcp::socket& socket;

    boost::filesystem::path root_directory;
    boost::filesystem::path working_directory;

    std::string rename_from_path;

  //////////////////////////////////
  /// Constructor
  //////////////////////////////////
  public:
    explicit FtpSession(boost::asio::io_service&, boost::asio::ip::tcp::socket& socket);

  //////////////////////////////////
  /// public API
  //////////////////////////////////
  public:
    void set_root_directory(const boost::filesystem::path& root_directory);

  //////////////////////////////////
  /// FTP console callbacks
  //////////////////////////////////
  public:
    FtpResult set_username(const std::string& username);
    FtpResult set_password(const std::string& password);
    FtpResult quit();
    FtpResult set_port(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
    FtpResult set_type(const FtpTransferType& type);
    FtpResult get_system();
    FtpResult set_mode(unsigned char mode);
    FtpResult set_file_structure(unsigned char stru);
    FtpResult get_working_directory();
    FtpResult create_new_directory(const std::string& directory);
    FtpResult change_working_directory(const std::string& directory);
    FtpResult remove_directory(const std::string& directory);
    FtpResult remove_file(const std::string& filemane);
    FtpResult rename_file_from(const std::string& filemane);
    FtpResult rename_file_to(const std::string& filemane);
    FtpResult get_size(const std::string& filename);
    FtpResult set_passive();
    FtpResult store(const std::string& filename);
    FtpResult no_operation();

    void retrieve(const std::string& filename, std::function<void(const FtpResult&)> cb);
    void store(const std::string& filename, std::function<void(const FtpResult&)> cb);
    void list(std::function<void(const FtpResult&)> cb);

  //////////////////////////////////
  /// Helper functions
  //////////////////////////////////
  private:
    boost::filesystem::path to_local_path(const std::string& ftp_path);
  };

}
