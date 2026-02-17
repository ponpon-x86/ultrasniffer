#include "handler.hpp"

bool Handler::openWriter() {
    writer = std::make_unique<pcpp::PcapFileWriterDevice>(output_filename);
    // try to open the file for writing
    return writer->open();
}

void Handler::run() {
    while (true) {
        pcpp::RawPacket packet;
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [this] { return !queue.empty() || killswitch_ref; });

            if (queue.empty() && killswitch_ref) break; // can die

            packet = std::move(queue.front());
            queue.pop();
        }

        if (writer) {
            writer->writePacket(packet);
        }
    }
}