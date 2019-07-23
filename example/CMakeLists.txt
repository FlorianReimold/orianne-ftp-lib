cmake_minimum_required(VERSION 3.5.1)

project(example)

set(CMAKE_CXX_STANDARD 11)

set(Boost_USE_STATIC_LIBS   ON)

find_package(Boost 1.46.0 REQUIRED COMPONENTS system)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
	link_directories(${Boost_LIBRARY_DIRS})
endif()

set(sources
    src/main.cpp
)

add_executable (${PROJECT_NAME}
    ${sources}
)

target_link_libraries (${PROJECT_NAME}
    orianne-ftp
	Boost::system
)
