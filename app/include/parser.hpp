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

// ----------------------------
// FTP
// ----------------------------

enum Type {
    CONTROL,
    DATA,
    TCP_CLEAN,
    OTHER,
    TCP_PART,
    UNKNOWN,
    UNWANTED,
    TCP_DROP
};

struct ControlSessionKey {
    uint32_t server_ip, client_ip;

    ControlSessionKey(uint32_t server_ip, uint32_t client_ip) 
        : server_ip(server_ip), client_ip(server_ip) {}

    bool operator<(const ControlSessionKey& other) const {
        return std::tie(server_ip, client_ip) < std::tie(other.server_ip, other.client_ip);
    }
};

struct FtpDataSessionKey {
    uint32_t server_ip, client_ip;
    uint16_t port;

    FtpDataSessionKey(uint32_t server_ip, uint32_t client_ip, uint16_t port) 
        : server_ip(server_ip), client_ip(server_ip), port(port) {}

    bool operator<(const FtpDataSessionKey& other) const {
        return std::tie(server_ip, client_ip, port) < std::tie(other.server_ip, other.client_ip, other.port);
    }
};

// ----------------------------
// TCP
// ----------------------------

// this is like 5-tuple except it's always tcp
struct TcpConnectionKey {
    uint32_t ip1, ip2;
    uint16_t port1, port2;
    
    TcpConnectionKey(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) 
    {
        if (std::tie(src_ip, src_port) < std::tie(dst_ip, dst_port)) {
            ip1 = src_ip; ip2 = dst_ip; port1 = src_port; port2 = dst_port;
        } else {
            ip1 = dst_ip; ip2 = src_ip; port1 = dst_port; port2 = src_port;
        }
    }

    bool operator<(const TcpConnectionKey& other) const {
        return std::tie(ip1, ip2, port1, port2) < std::tie(other.ip1, other.ip2, other.port1, other.port2);
    }
};

// for checking 3-way handshake && ready-ness
struct TcpConnectionState {
    std::vector<pcpp::RawPacket> packets;

    // we can know who initiated the connection from the first syn
    uint32_t client_ip;
    uint16_t client_port;

    // to check ... out-of-order stuff
    uint32_t next_server_seq = 0;
    uint32_t next_client_seq = 0;

    // stats
    bool handshake_complete = false;
    bool perfect_closure = false;
    bool fin_from_client = false;
    bool fin_from_server = false;
    bool last_ack_from_client = false;
    bool last_ack_from_server = false;
    bool is_failed = false;

    long last_activity;

    TcpConnectionState(uint32_t client_ip, uint16_t client_port) :
        client_ip(client_ip), client_port(client_port) {};
};

// ----------------------------
// UDP
// ----------------------------

// this is like 5-tuple except it's always udp
struct UdpConnectionKey {
    uint32_t ip1, ip2;
    uint16_t port1, port2;
    
    UdpConnectionKey(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) 
    {
        if (std::tie(src_ip, src_port) < std::tie(dst_ip, dst_port)) {
            ip1 = src_ip; ip2 = dst_ip; port1 = src_port; port2 = dst_port;
        } else {
            ip1 = dst_ip; ip2 = src_ip; port1 = dst_port; port2 = src_port;
        }
    }

    bool operator<(const UdpConnectionKey& other) const {
        return std::tie(ip1, ip2, port1, port2) < std::tie(other.ip1, other.ip2, other.port1, other.port2);
    }
};

// for ignoring clients
struct UdpConnectionState {
    uint32_t client_ip;
    uint16_t client_port;
    long last_activity;
    UdpConnectionState(uint32_t client_ip, uint16_t client_port) :
        client_ip(client_ip), client_port(client_port) {};
};

// ----------------------------

class Parser {

public:

    Parser() = delete;
    Parser(
        std::array<std::queue<pcpp::RawPacket>, 4>& shared_queues,
        std::array<std::mutex, 4>& shared_mutexes,
        std::array<std::condition_variable, 4>& shared_cvs,
        std::atomic<bool>& shared_killswitch
    ) : queues(shared_queues), 
        mutexes(shared_mutexes), 
        cvs(shared_cvs),
        killswitch_ref(shared_killswitch)
    {};

    void parse(std::string);

private:

    bool is_pcap_file(const std::string&);
    void processFile(const std::string&);
    Type determinePacketType(const pcpp::RawPacket&);
    TcpConnectionKey recombineTcpKey(const pcpp::RawPacket&);

    bool isUdp(const pcpp::RawPacket&);
    bool shouldIgnoreUdp(const pcpp::RawPacket&);
    void ignoreMessage(const pcpp::RawPacket&);

    unsigned cleaner_counter = 0;

    std::array<std::queue<pcpp::RawPacket>, 4>& queues;
    std::array<std::mutex, 4>& mutexes;
    std::array<std::condition_variable, 4>& cvs;
    std::atomic<bool>& killswitch_ref;

    // -------
    // FTP
    // -------

    const std::regex passive_mode { R"(.*227 Entering Passive Mode.*\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\).*)" };
    const std::regex port { R"(.*PORT[^a-zA-Z0-9]*(\d+),(\d+),(\d+),(\d+),(\d+),(\d+).*)" };

    std::set<FtpDataSessionKey> active_data_sessions;
    std::set<ControlSessionKey> awaiting_passive_response;

    // -------
    // TCP
    // -------

    std::map<TcpConnectionKey, TcpConnectionState> tcp_connections;
    std::map<UdpConnectionKey, UdpConnectionState> udp_connections;
};