# orianne-ftp-lib
Orianne is a minimal FTP server library for Windows and Unix flavours. The project is CMake based and only depends on asio, which is integrated as git submodule. No boost is required.

You can easily embedd this library into your own project in order to create an embedded FTP Server. It was developed and tested on Windows 10 and Ubuntu 16.04.

## Features:
- Listing directories
- Uploading and downloading files
- Creating and removing files and directories
- Multiple connections

## Security
- None :)

=> No authentication, no encryption.
*You should only use orianne in trusted networks!*

## How to checkout and build
There is an example project provided that will create an FTP Server at `C:\` (Windows) or `/` (Unix).

1. Install cmake and git / git-for-windows
	
2. Checkout this repo and the asio submodule
	```console
	git checkout https://github.com/FlorianReimold/orianne-ftp-lib.git
	cd orianne-ftp-lib
	git submodule init
	git submodule update
	```
	
3. CMake the project *(Building as debug will add some debug output that is helpfull so see if everything is working)*
	```console
	mkdir build
	cd build
	cmake .. -DCMAKE_BUILD_TYPE=Debug
	```

4. Build the project
	- Linux: `make`
	- Windows: Open `build\orianne.sln` with Visual Studio and build the example project

5. Start `example` / `example.exe` and connect with your favourite FTP Client (e.g. FileZilla) on port 2121 *(This port is used so you don't need root privileges to start the FTP server)*
