#pragma once

#include <iostream>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include <unordered_set>

#include <regex>
#include <map>
#include <set>

#include <Packet.h>
#include <RawPacket.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IPv4Layer.h>

#include <filesystem>
namespace fs = std::filesystem;

class Handler {

public:
    Handler() = delete;
    Handler(
        std::string output_filename,
        std::queue<pcpp::RawPacket>& queue,
        std::mutex& mutex,
        std::condition_variable& cv,
        std::atomic<bool>& killswitch_ref
    ) :
        output_filename(output_filename),
        queue(queue), 
        mutex(mutex), 
        cv(cv),
        killswitch_ref(killswitch_ref)
    {};

    bool openWriter();
    void run();
private:
    std::string output_filename;
    std::queue<pcpp::RawPacket>& queue;
    std::mutex& mutex;
    std::condition_variable& cv;
    std::atomic<bool>& killswitch_ref;

    std::unique_ptr<pcpp::PcapFileWriterDevice> writer;
};