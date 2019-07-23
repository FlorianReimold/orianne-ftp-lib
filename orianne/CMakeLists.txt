cmake_minimum_required(VERSION 3.5.1)

project(orianne-ftp)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)

find_package(Boost 1.46.0 REQUIRED COMPONENTS filesystem system)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
endif()

set (includes
    include/orianne/ftp_server.h
)

set(sources
    src/ftp_console.cpp
    src/ftp_console.h
    src/ftp_server.cpp
    src/ftp_session.cpp
    src/ftp_session.h
)

add_library (${PROJECT_NAME}
    ${includes}
    ${sources}
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
	    Boost::system
		Boost::filesystem
)

#target_compile_definitions(${PROJECT_NAME} ASIO_STANDALONE)

target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_include_directories(${PROJECT_NAME} PRIVATE src/)
