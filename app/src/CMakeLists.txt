file(GLOB_RECURSE SOURCES 
    *.cpp
    ${PROJECT_SOURCE_DIR}/app/include/*.h
    ${PROJECT_SOURCE_DIR}/app/include/*.hpp
)

find_package(PcapPlusPlus REQUIRED)
add_executable(ultrasniffer ${SOURCES})

target_link_libraries(ultrasniffer PUBLIC PcapPlusPlus::Pcap++ PcapPlusPlus::Common++)
# target_include_directories(ultrasniffer PRIVATE ${PROJECT_SOURCE_DIR}/include)
install(TARGETS ultrasniffer DESTINATION .)