cmake_minimum_required(VERSION 3.5.1)

# Normalize backslashes from Windows paths
#file(TO_CMAKE_PATH "${CMAKE_MODULE_PATH}" CMAKE_MODULE_PATH)
#file(TO_CMAKE_PATH "${CMAKE_PREFIX_PATH}" CMAKE_PREFIX_PATH)
#file(TO_CMAKE_PATH "${BOOST_ROOT}" BOOST_ROOT)
#message(STATUS "Module Path: ${CMAKE_MODULE_PATH}")
#message(STATUS "Prefix Path: ${CMAKE_PREFIX_PATH}")
#message(STATUS "Boost root: ${BOOST_ROOT}")


project(orianne)

add_subdirectory(orianne)
add_subdirectory(example)
