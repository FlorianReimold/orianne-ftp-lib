cmake_minimum_required(VERSION 3.5.1)

project(orianne-ftp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)
find_package(asio REQUIRED)

#set(Boost_USE_STATIC_LIBS   ON)
#find_package(Boost 1.46.0 REQUIRED COMPONENTS system)
#if (Boost_FOUND)
#    include_directories(${Boost_INCLUDE_DIR})
#endif()

# Public API include directory
set (includes
    include/orianne/ftp_server.h
)

# Private source files
set(sources
    src/filesystem.cpp
    src/filesystem.h
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

add_library (orianne::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

#target_link_libraries(${PROJECT_NAME}
#    PUBLIC
#        Boost::system
#)
target_link_libraries(${PROJECT_NAME}
    PUBLIC
        asio::asio
)

target_compile_definitions(${PROJECT_NAME} PUBLIC ASIO_STANDALONE)
target_compile_definitions(${PROJECT_NAME} PUBLIC __USE_FILE_OFFSET64=1)

# Add Boost include directory
#target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIR})

# Add own public include directory
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                                                  $<INSTALL_INTERFACE:include>)
target_include_directories(${PROJECT_NAME} PRIVATE src/)


##################################

SET(${PROJECT_NAME}_INSTALL_CMAKE_DIR "lib/cmake/${PROJECT_NAME}")

INSTALL(
  TARGETS ${PROJECT_NAME} 
  EXPORT ${PROJECT_NAME}Targets 
  LIBRARY DESTINATION "lib" 
  ARCHIVE DESTINATION "lib"   
  COMPONENT dev
)

INSTALL(DIRECTORY "include/orianne" DESTINATION "include" COMPONENT dev FILES_MATCHING PATTERN "*.h")
INSTALL(
  EXPORT ${PROJECT_NAME}Targets 
  FILE ${PROJECT_NAME}Targets.cmake 
  DESTINATION ${${PROJECT_NAME}_INSTALL_CMAKE_DIR}
  NAMESPACE orianne::
)

INCLUDE(CMakePackageConfigHelpers)

configure_package_config_file(
  "../cmake/${PROJECT_NAME}Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cmake/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION ${${PROJECT_NAME}_INSTALL_CMAKE_DIR}
  PATH_VARS ${PROJECT_NAME}_INSTALL_CMAKE_DIR
)
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/cmake/${PROJECT_NAME}Config.cmake" DESTINATION ${${PROJECT_NAME}_INSTALL_CMAKE_DIR})

