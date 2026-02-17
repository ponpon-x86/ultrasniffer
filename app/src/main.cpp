#include <iostream>
#include <filesystem>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

#include <Packet.h>
#include <RawPacket.h>
#include <PcapFileDevice.h>

namespace fs = std::filesystem;

#include "parser.hpp"
#include "handler.hpp"

// there may be more extensions, these are the ones i found
bool is_pcap_file(const fs::path& p) {
    static const std::unordered_set<std::string> extensions = {
        ".pcap", ".pcapng", ".cap"
    };

    std::string ext = p.extension().string();
    return (extensions.count(ext));
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "\n\tERROR: please specify exactly one argument (path to .pcap file or folder).\n\t";
        return 1;
    }

    // so what do i want
    std::array<std::queue<pcpp::RawPacket>, 4> queues; // a queue for each type of data
    std::array<std::mutex, 4> mutexes;
    std::array<std::condition_variable, 4> cv; // for pausing queues
    std::atomic<bool> killswitch {false}; // for stopping everything
    std::array<const std::string, 4> output = { "ftp.pcap", "ftp_data.pcap", "tcp_clean.pcap", "other.pcap" };

    std::vector<Handler> handlers; 
    std::vector<std::thread> threads;
    handlers.reserve(4);
    for (int i = 0; i < 4; ++i) {
        handlers.emplace_back(output.at(i), queues.at(i), mutexes.at(i), cv.at(i), killswitch);
        handlers.at(i).openWriter();
        Handler& h = handlers.back();
        threads.emplace_back([&h]() { 
            h.run(); 
        });
    }

    Parser parser(queues, mutexes, cv, killswitch);
    parser.parse(argv[1]);

    killswitch = true;
    for (auto& thread : threads)
        thread.join();

    return 0;
}