#include "parser.hpp"

bool Parser::is_pcap_file(const std::string& ext) {
    static const std::unordered_set<std::string> extensions = {
        ".pcap"
    };

    return (extensions.count(ext));
}

// -----------------------------

void Parser::parse(std::string arg) {
    fs::path target(arg);
    if (!fs::exists(target)) {
        std::cout << "\n\tERROR: specified argument is not found.\n\t";
        return;
    }

    if (fs::is_directory(target)) {
        std::cout << "\n\tNOTE: specified argument is a directory.\n\t";

        for (const auto& entry : fs::directory_iterator(target)) {
            if (is_pcap_file(entry.path().extension().string())) {
                std::cout << "\n\tNOTE: processing file\n\t<" << entry.path().string() << ">\n\t";
                processFile(entry.path().string());
            }
        }
    } else if (fs::is_regular_file(target)) {
        if (is_pcap_file(target.extension().string())) {
            std::cout << "\n\tNOTE: specified argument is a .pcap file.\n\t";
            std::cout << "\n\tNOTE: processing file\n\t<" << target.string() << ">\n\t";
            processFile(target.string());
        } else { 
            std::cout << "\n\tERROR: specified argument is a file, but not a .pcap one.\n\t";
            return;
        }
    } else {
        std::cout << "\n\tERROR: specified argument is not a file nor a directory.\n\t";
        return;
    }

    return;
}

void Parser::ignoreMessage(const pcpp::RawPacket& raw_packet) {
    pcpp::Packet packet(const_cast<pcpp::RawPacket*>(&raw_packet));
    pcpp::UdpLayer* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
    pcpp::IPv4Layer* ip_v4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();

    if (!ip_v4_layer || !udp_layer) return;

    auto src_port = udp_layer->getSrcPort();
    auto dst_port = udp_layer->getDstPort();
    pcpp::IPv4Address src_ip = ip_v4_layer->getSrcIPv4Address();
    pcpp::IPv4Address dst_ip = ip_v4_layer->getDstIPv4Address();

    std::time_t now = std::time(nullptr);
    std::tm* local_time_info = std::localtime(&now);

    std::cout << "\tHandler 4:\n\t" << 
        std::put_time(local_time_info, "%Y-%m-%d %H:%M:%S") << 
        " // UDP packet " << src_ip << ":" << src_port << " -> " << dst_ip << ":" << dst_port << " is being ignored.\n";
}

void Parser::processFile(const std::string& file) {
    // the idea here is to fire a reader,
    // try to open the file, and enter a loop.
        // get the packet
        // determine the packet category
        // emplace it in a queue
        // and notify 

    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(file);
    if (reader == NULL) {
        std::cout << "\n\tERROR: cannot determine reader for this file type.\n\t";
        return;
    }
    if (!reader->open()) {
        std::cout << "\n\tERROR: cannot open file <" << file << "> for reading.\n\t";
        return;
    }

    pcpp::RawPacket raw_packet;
    while (reader->getNextPacket(raw_packet)) {
        // std::cout << "\n\tNext packet. ";
        // here we have to determine the type of the packet
        Type result;
        if (isUdp(raw_packet))
            if (shouldIgnoreUdp(raw_packet)) { // check for udp
                result = Type::UNWANTED;
                ignoreMessage(raw_packet);
            }
            else result = Type::OTHER;
        else result = determinePacketType(raw_packet); // checks for tcp
        // std::cout << "Todo code: " << result << ". ";

        switch (result)
        {
            case CONTROL:
            {
                std::unique_lock<std::mutex> lock(mutexes.at(CONTROL));
                queues.at(CONTROL).emplace(raw_packet); // raw packet needed for writing
            }
            cvs.at(CONTROL).notify_one();
            break;
            case DATA:
            {
                std::unique_lock<std::mutex> lock(mutexes.at(DATA));
                queues.at(DATA).emplace(raw_packet);
            }
            cvs.at(DATA).notify_one();
            break;
            case TCP_CLEAN:
            {
                auto key = recombineTcpKey(raw_packet);
                {
                    std::unique_lock<std::mutex> lock(mutexes.at(TCP_CLEAN));
                    auto it = tcp_connections.find(key);
                    if (it != tcp_connections.end()) {
                        auto& connection = it->second;
                        for(auto& pack : connection.packets)
                            queues.at(TCP_CLEAN).emplace(raw_packet);
                    }
                }
                cvs.at(TCP_CLEAN).notify_one();
                tcp_connections.erase(key);
            }
            break;
            case TCP_DROP:
            {
                auto key = recombineTcpKey(raw_packet);
                {
                    std::unique_lock<std::mutex> lock(mutexes.at(OTHER));
                    auto it = tcp_connections.find(key);
                    if (it != tcp_connections.end()) {
                        auto& connection = it->second;
                        for(auto& pack : connection.packets)
                            queues.at(OTHER).emplace(raw_packet);
                    }
                    queues.at(OTHER).emplace(raw_packet);
                }
                cvs.at(OTHER).notify_one();
                tcp_connections.erase(key);
            }
            break;
            case OTHER:
            {
                std::unique_lock<std::mutex> lock(mutexes.at(OTHER));
                queues.at(OTHER).emplace(raw_packet);
            }
            cvs.at(OTHER).notify_one();
            break;
        }
        ++cleaner_counter;

        // get rid of all the corpses
        if (cleaner_counter >= 500) {
            long current_time = time(nullptr);

            for (auto it = udp_connections.begin(); it != udp_connections.end(); ) {
                if (current_time - it->second.last_activity > 60) it = udp_connections.erase(it); 
                else ++it;
            }

            for (auto it = tcp_connections.begin(); it != tcp_connections.end(); ) {
                if (current_time - it->second.last_activity > 300) it = tcp_connections.erase(it);
                else ++it;
            }
            cleaner_counter = 0; // reset
        }
    } // while (reader->getNextPacket(raw_packet))
    delete reader;
    std::cout << "\n\n\tDone.\n\n\t";
}

//

bool Parser::isUdp(const pcpp::RawPacket& raw_packet) {
    // crutch
    pcpp::Packet packet(const_cast<pcpp::RawPacket*>(&raw_packet));
    pcpp::UdpLayer* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
    return !(udp_layer == nullptr);
}

bool Parser::shouldIgnoreUdp(const pcpp::RawPacket& raw_packet) {
    // 4 UDP

    pcpp::Packet packet(const_cast<pcpp::RawPacket*>(&raw_packet));
    pcpp::UdpLayer* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>();
    pcpp::IPv4Layer* ip_v4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();

    if (!udp_layer || !ip_v4_layer) return true; // why are we still here

    // if it is a udp connection && 
    // client's port is any in range of 20000-25000,
    // ignore it
    auto src_port = udp_layer->getSrcPort();
    auto dst_port = udp_layer->getDstPort();
    pcpp::IPv4Address src_ip = ip_v4_layer->getSrcIPv4Address();
    pcpp::IPv4Address dst_ip = ip_v4_layer->getDstIPv4Address();

    UdpConnectionKey key = { src_ip.toInt(), dst_ip.toInt(), src_port, dst_port };
    auto it = udp_connections.find(key);
    if (it == udp_connections.end()) {
        // first package. udp is inited by client.
        auto [it, flag] = udp_connections.try_emplace(key, src_ip.toInt(), src_port);
        it->second.last_activity = time(nullptr);
        
        if (src_port >= 20000 && src_port <= 25000) return true;
    } else {
        it->second.last_activity = time(nullptr); // shock therapy
        // an existing sesh. check whether client or server sent it:
        if (src_ip == it->second.client_ip && src_port == it->second.client_port) {
            // it's FROM the client
            if (src_port >= 20000 && src_port <= 25000) return true;
        } else {
            // from server TO client
            if (dst_port >= 20000 && dst_port <= 25000) return true;
        }
    }

    return false;
}

TcpConnectionKey Parser::recombineTcpKey(const pcpp::RawPacket& raw_packet) {
    pcpp::Packet packet(const_cast<pcpp::RawPacket*>(&raw_packet));
    pcpp::TcpLayer* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    pcpp::IPv4Layer* ip_v4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::IPv4Address src_ip = ip_v4_layer->getSrcIPv4Address();
    pcpp::IPv4Address dst_ip = ip_v4_layer->getDstIPv4Address();
    auto src_port = tcp_layer->getSrcPort();
    auto dst_port = tcp_layer->getDstPort();
    return { src_ip.toInt(), dst_ip.toInt(), src_port, dst_port }; // sorted key
}

Type Parser::determinePacketType(const pcpp::RawPacket& raw_packet) {
    // get the tcp layer
    pcpp::Packet packet(const_cast<pcpp::RawPacket*>(&raw_packet));
    pcpp::TcpLayer* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
    pcpp::IPv4Layer* ip_v4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();

    // something went wrong:
    if (!tcp_layer || !ip_v4_layer) return UNKNOWN;

    auto src_port = tcp_layer->getSrcPort();
    auto dst_port = tcp_layer->getDstPort();
    pcpp::IPv4Address src_ip = ip_v4_layer->getSrcIPv4Address();
    pcpp::IPv4Address dst_ip = ip_v4_layer->getDstIPv4Address();
    auto payload = tcp_layer->getLayerPayload();
    auto payload_len = tcp_layer->getLayerPayloadSize();
    auto header = tcp_layer->getTcpHeader();

    // 1. CONTROL
    // ftp control is happening over port 21
    if (src_port == 21 || dst_port == 21) {
        if (payload_len > 0) {
            std::string payload_str((char*)payload, payload_len);
            std::smatch smatch;
            if (src_port == 21) { // SERVER -> CLIENT
                if (std::regex_search(payload_str, smatch, passive_mode)) { 
                    // regex against "227 Entering..."
                    uint16_t data_port = std::stoi(smatch[smatch.size() - 2]) * 256 + std::stoi(smatch[smatch.size() - 1]);
                    ControlSessionKey session = { src_ip.toInt(), dst_ip.toInt() };
                    if (awaiting_passive_response.count(session)) {
                        awaiting_passive_response.erase(session);
                        active_data_sessions.insert({ src_ip.toInt(), dst_ip.toInt(), data_port });
                    }
                }
            } else { // CLIENT -> SERVER
                if (std::regex_search(payload_str, smatch, port)) {
                    uint16_t data_port = std::stoi(smatch[smatch.size() - 2]) * 256 + std::stoi(smatch[smatch.size() - 1]);
                    active_data_sessions.insert({ dst_ip.toInt(), src_ip.toInt(), data_port });
                } else if (payload_str.find("PASV") != std::string::npos) {
                    awaiting_passive_response.insert({ dst_ip.toInt(), src_ip.toInt() });
                }
            }
        }

        return CONTROL;
    }

    // 2.1 DATA (RANDOM PORT)
    // usually ftp data would be handled over port 20,
    // but in pasv situation it could be anything

    for (auto it = active_data_sessions.begin(); it != active_data_sessions.end(); ) {
        // not sure about PORT command (?),
        // for passive mode this would be server to client
        bool is_server_to_client = (src_ip.toInt() == it->server_ip && dst_ip.toInt() == it->client_ip && src_port == it->port);
        // and vice versa
        bool is_client_to_server = (src_ip.toInt() == it->client_ip && dst_ip.toInt() == it->server_ip && dst_port == it->port);
        
        if (is_server_to_client || is_client_to_server) {
            // at this point we know it should be data
            
            // delete the entry if there's a fin flag, lest it will hang in mem
            if (header->finFlag == 1 || header->rstFlag == 1) {
                it = active_data_sessions.erase(it);
            } else {
                ++it;
            }

            return DATA;
        } else ++it;
    }

    // 2.2 DATA (DEFAULT PORT)
    if (src_port == 20 || dst_port == 20) {
        return DATA;
    }

    // 3 TCP
    bool syn = (header->synFlag == 1); // on 2nd step there must be both
    bool ack = (header->ackFlag == 1); // syn and ack.
    bool fin = (header->finFlag == 1);
    bool rst = (header->rstFlag == 1);

    uint32_t seq = header->sequenceNumber;
    // sorted key
    TcpConnectionKey key { src_ip.toInt(), dst_ip.toInt(), src_port, dst_port };

    // actually, we can check, i guess, for rst flag right away
    // it would be non-perfect tcp sesh

    auto it = tcp_connections.find(key);
    if (rst) {
        if (!(it == tcp_connections.end())) it->second.is_failed = true;
        return TCP_DROP;
    }

    if (it == tcp_connections.end()) {
        if (syn && !ack) { // (1) new connection, CLIENT -> SERVER
            auto [it, flag] = tcp_connections.try_emplace(key, src_ip.toInt(), src_port); // client's ip / port
            uint32_t packet_seq = ntohl(header->sequenceNumber);
            it->second.next_client_seq = packet_seq + 1;
            it->second.next_server_seq = 0;
            it->second.packets.push_back(raw_packet);
            it->second.last_activity = time(nullptr);
            return TCP_PART;
        } else {
            // else it's some sort of out of order situation / non-perfect tcp
            // connection doesnt' exist, but there are flags other than syn
            return OTHER; // ?
        }
    } else { // existing connection
        TcpConnectionState& connection_state = it->second;

        // client sends something:
        if (src_ip == connection_state.client_ip && src_port == connection_state.client_port) {
            if (!syn && ack && !connection_state.handshake_complete) {
                uint32_t current_ack = ntohl(header->ackNumber); 
                if (current_ack == connection_state.next_server_seq) {
                    connection_state.handshake_complete = true; // (3) finally shook hands, ready for data
                    connection_state.next_client_seq = ntohl(header->sequenceNumber); // i hope.
                    connection_state.packets.push_back(raw_packet);
                    connection_state.last_activity = time(nullptr); // shock therapy
                    return TCP_PART;
                }
            } else { // else it should just be data
                uint32_t seq = ntohl(header->sequenceNumber);
                uint32_t expected_seq = connection_state.next_client_seq;
                if (seq != expected_seq) {
                    connection_state.is_failed = true; // reason: out of order or RE



                    return TCP_DROP;
                }

                uint32_t fin_size = (fin) ? 1 : 0;
                connection_state.next_client_seq = seq + (uint32_t)payload_len + fin_size;
                if (fin) connection_state.fin_from_client = true;
                // again, client sends something
                if (ack && connection_state.fin_from_server) {
                    // check if this is acknowledgement of server's fin
                    if (ntohl(header->ackNumber) == connection_state.next_server_seq /* +1, but it was made above */) {
                        connection_state.perfect_closure = true; // no final words, perfect closure
                    }
                }
                connection_state.packets.push_back(raw_packet); // push packet
                if (connection_state.perfect_closure) { // if it's ok to close
                    if (!connection_state.is_failed && connection_state.handshake_complete) {
                        return TCP_CLEAN; 
                        // the key will be recomposed in the outer function
                        // which will allow to delete the sesh from std map
                        // and check the connection_state.is_failed flag
                        // to see if all the packages should fly to OTHER group
                    }
                }
                connection_state.last_activity = time(nullptr); // shock therapy
                return TCP_PART;
            }
        } else { // else server sends something
            if (syn && ack) { // (2) server handshake response, SERVER -> CLIENT
                uint32_t seq = ntohl(header->sequenceNumber);
                connection_state.next_server_seq = seq + 1;
                if (ntohl(header->ackNumber) != connection_state.next_client_seq) { // check if handshake is correct?
                    connection_state.is_failed = true;
                    return TCP_DROP;
                }
                connection_state.packets.push_back(raw_packet);
                connection_state.last_activity = time(nullptr); // shock therapy
                return TCP_PART;
            } else { // else it should just be data
                uint32_t seq = ntohl(header->sequenceNumber);
                uint32_t expected_seq = connection_state.next_server_seq;
                if (seq != expected_seq) {
                    connection_state.is_failed = true; // reason: out of order or RE
                    return TCP_DROP;
                }

                uint32_t fin_size = (fin) ? 1 : 0;
                connection_state.next_server_seq = seq + (uint32_t)payload_len + fin_size;
                if (fin) connection_state.fin_from_server = true;
                // again, server sends something
                if (ack && connection_state.fin_from_client) {
                    // check if this is acknowledgement of server's fin
                    if (ntohl(header->ackNumber) == connection_state.next_client_seq /* +1, but it was made above */) {
                        connection_state.perfect_closure = true; // no final words, perfect closure
                    }
                }
                connection_state.packets.push_back(raw_packet); // push packet
                if (connection_state.perfect_closure) { // if it's ok to close
                    if (!connection_state.is_failed && connection_state.handshake_complete) {
                        return TCP_CLEAN; 
                        // the key will be recomposed in the outer function
                        // which will allow to delete the sesh from std map
                        // and check the connection_state.is_failed flag
                        // to see if all the packages should fly to OTHER group
                    }
                }
                connection_state.last_activity = time(nullptr); // shock therapy
                return TCP_PART;
            }
        }
    }

    return OTHER;
}