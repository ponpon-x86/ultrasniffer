cmake_minimum_required(VERSION 3.10.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(ultrasniffer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PcapPlusPlus REQUIRED)

include_directories(
    ${PROJECT_SOURCE_DIR}/app/include
)

add_subdirectory(app)