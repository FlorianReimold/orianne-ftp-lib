cmake_minimum_required(VERSION 3.5.1)

project(orianne-ftp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)

set(Boost_USE_STATIC_LIBS   ON)
find_package(Boost 1.46.0 REQUIRED COMPONENTS filesystem system)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
endif()

# Public API include directory
set (includes
    include/orianne/ftp_server.h
)

# Private source files
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
    PUBLIC
        Boost::system
    PRIVATE
        Boost::filesystem
)

#target_compile_definitions(${PROJECT_NAME} ASIO_STANDALONE)
target_compile_definitions(${PROJECT_NAME} PUBLIC __USE_FILE_OFFSET64=1)

# Add Boost include directory
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIR})

# Add own public include directory
target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_include_directories(${PROJECT_NAME} PRIVATE src/)

