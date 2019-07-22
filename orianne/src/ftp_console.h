#pragma once

#include "stdafx.h"

#include "ftp_session.h"

#include <map>

namespace orianne {

  class FtpConsole {
  public:
    typedef boost::function<void(const std::string&)> write_message_func;
    typedef boost::function<void(const std::string&, FtpSession&, write_message_func&)> command_func;

    FtpConsole(FtpSession& _session);
    void read_line(const std::string& mesg);
    void set_write_callback(write_message_func wm);
    const std::string& greeter();

  private:
    FtpSession& session;
    write_message_func write_message;
    std::string greeter_;

    static std::map<std::string, command_func>& commands();
  };

}
