#include <iostream>
#include <iomanip>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <fstream>
#include <filesystem>
#include <limits>
#include <stdexcept>

using namespace std;

int i = 1;

#pragma pack(push, 1)

struct EthernetHeader
{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct IPHeader
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct TCPHeader
{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

#pragma pack(pop)

struct RawPacketItem
{
    pcap_pkthdr header;
    vector<u_char> data;
};

class CircularRingBuffer
{
private:
    vector<RawPacketItem> buffer_;
    size_t capacity_;
    size_t head_ = 0;
    size_t tail_ = 0;
    size_t count_ = 0;
    bool finished_ = false;

    mutex mutex_;
    condition_variable not_full_;
    condition_variable not_empty_;

public:

    CircularRingBuffer(size_t capacity = 2048)
        : capacity_(capacity), buffer_(capacity) {}

    bool enqueue(const struct pcap_pkthdr* head,
                 const u_char* packet)
    {
        unique_lock<mutex> lock(mutex_);

        if (count_ == capacity_)
            return false;

        buffer_[tail_].header = *head;

        buffer_[tail_].data.assign(
            packet, packet + head->caplen);

        tail_ = (tail_ + 1) % capacity_;
        count_++;

        lock.unlock();
        not_empty_.notify_one();

        return true;
    }

    bool dequeue(RawPacketItem& item)
    {
        unique_lock<mutex> lock(mutex_);

        while (count_ == 0 && !finished_)
            not_empty_.wait(lock);

        if (count_ == 0 && finished_)
            return false;

        item = buffer_[head_];

        head_ = (head_ + 1) % capacity_;
        count_--;

        lock.unlock();
        not_full_.notify_one();

        return true;
    }

    void setFinished()
    {
        unique_lock<mutex> lock(mutex_);
        finished_ = true;

        lock.unlock();
        not_empty_.notify_all();
    }
};

class NetworkAnalyzer
{
public:

    void printHex(const u_char* packet,
                  size_t start, size_t length)
    {
        cout << "Data : ";

        for (size_t j = start; j < start + length; j++)
        {
            cout << hex << setw(2) << setfill('0')
                 << (int)packet[j] << " ";
        }

        cout << dec << setfill(' ');
    }

    void printHex(const u_char* packet,
                  uint32_t total_length)
    {
        cout << "\nFULL RAW HEX DUMP:\n";

        for (uint32_t j = 0; j < total_length; j++)
        {
            cout << hex << setw(2) << setfill('0')
                 << (int)packet[j] << " ";

            if ((j + 1) % 16 == 0 || j + 1 == total_length)
                cout << endl;
        }

        cout << dec << setfill(' ');
    }
};

class TCPPacketAnalyzer : public NetworkAnalyzer
{
private:

    ofstream csvFile;

public:

    TCPPacketAnalyzer()
    {
        char choice;
        cout << "Do you want to create a CSV file for this program? (y/n): ";
        cin >> choice;

        if (choice != 'y' && choice != 'Y')
            return;

        string filename;

        while (true)
        {
            cout << "Enter CSV filename: ";
            cin >> filename;

            if (filename.size() < 4 || filename.substr(filename.size() - 4) != ".csv")
                filename += ".csv";

            try
            {
                if (filesystem::exists(filename))
                    throw runtime_error("File already exists!");

                csvFile.clear();
                csvFile.open(filename, ios::out);

                if (!csvFile.is_open())
                    throw runtime_error("Unable to create/open CSV file!");

                cout << "CSV file created: " << filename << "\n";

                csvFile
                    << "Packet No,"
                    << "Source IP,"
                    << "Source Port,"
                    << "Destination IP,"
                    << "Destination Port,"
                    << "Sequence Number,"
                    << "Acknowledgment Number,"
                    << "TCP Header Length,"
                    << "Window Size,"
                    << "Checksum,"
                    << "Flags\n";

                break;
            }
            catch (const filesystem::filesystem_error& e)
            {
                cerr << "File system error: " << e.what() << "\n";
                cout << "Try another filename.\n";
            }
            catch (const runtime_error& e)
            {
                if (string(e.what()) == "File already exists!")
                {
                    cout << e.what() << "\n";
                    char overwrite;
                    cout << "Overwrite it? (y/n): ";
                    cin >> overwrite;

                    if (overwrite == 'y' || overwrite == 'Y')
                    {
                        csvFile.clear();
                        csvFile.open(filename, ios::out | ios::trunc);

                        if (csvFile.is_open())
                        {
                            cout << "CSV file overwritten: " << filename << "\n";
                            csvFile
                                << "Packet No,"
                                << "Source IP,"
                                << "Source Port,"
                                << "Destination IP,"
                                << "Destination Port,"
                                << "Sequence Number,"
                                << "Acknowledgment Number,"
                                << "TCP Header Length,"
                                << "Window Size,"
                                << "Checksum,"
                                << "Flags\n";
                            break;
                        }
                        else
                        {
                            cerr << "Unable to overwrite file. Try another filename.\n";
                        }
                    }
                    else
                    {
                        cout << "Choose another filename.\n";
                    }
                }
                else
                {
                    cerr << e.what() << " Try another filename.\n";
                }
            }
        }
    }

    void analyze(const struct pcap_pkthdr* header,
                 const u_char* packet)
    {
        if (header->caplen < sizeof(EthernetHeader))
            return;

        const auto* eth =
            reinterpret_cast<const EthernetHeader*>(packet);

        if (ntohs(eth->ether_type) != 0x0800)
            return;

        size_t eth_hdr_len = sizeof(EthernetHeader);

        if (header->caplen < eth_hdr_len + sizeof(IPHeader))
            return;

        const auto* ip =
            reinterpret_cast<const IPHeader*>(packet + eth_hdr_len);

        if (ip->protocol != 6)
            return;

        size_t ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;

        if (ip_hdr_len < sizeof(IPHeader))
            return;

        size_t tcp_offset = eth_hdr_len + ip_hdr_len;

        if (header->caplen < tcp_offset + sizeof(TCPHeader))
            return;

        const auto* tcp =
            reinterpret_cast<const TCPHeader*>(packet + tcp_offset);

        size_t tcp_hdr_len =
            ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;

        if (tcp_hdr_len < sizeof(TCPHeader) ||
            header->caplen < tcp_offset + tcp_hdr_len)
            return;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip->src_ip),
                  src_ip, INET_ADDRSTRLEN);

        inet_ntop(AF_INET, &(ip->dest_ip),
                  dst_ip, INET_ADDRSTRLEN);

        cout << "\nPacket Number: " << i << "\n";
        i++;

        cout << "\n";
        cout << "============================================================\n";
        cout << "                  TCP PACKET INFORMATION                    \n";
        cout << "============================================================\n";

        uint8_t f = tcp->flags;

        cout << left << setw(25) << "Source IP"
             << ": " << src_ip << "\n";

        cout << left << setw(25) << "Source Port"
             << ": " << ntohs(tcp->source_port) << "\n";

        cout << left << setw(25) << "Destination IP"
             << ": " << dst_ip << "\n";

        cout << left << setw(25) << "Destination Port"
             << ": " << ntohs(tcp->dest_port) << "\n";

        cout << left << setw(25) << "Sequence Number"
             << ": " << ntohl(tcp->seq_num) << "\n";

        cout << left << setw(25) << "Acknowledgment Number"
             << ": " << ntohl(tcp->ack_num) << "\n";

        cout << left << setw(25) << "TCP Header Length"
             << ": " << tcp_hdr_len << " bytes\n";

        cout << left << setw(25) << "Window Size"
             << ": " << ntohs(tcp->window_size) << "\n";

        cout << left << setw(25) << "Checksum"
             << ": 0x" << hex << ntohs(tcp->checksum)
             << dec << "\n";

        cout << left << setw(25) << "TCP Flags"
             << ": ";

        if (f & 0x20) cout << "URG ";
        if (f & 0x10) cout << "ACK ";
        if (f & 0x08) cout << "PSH ";
        if (f & 0x04) cout << "RST ";
        if (f & 0x02) cout << "SYN ";
        if (f & 0x01) cout << "FIN ";

        cout << "\n";
        cout << "============================================================\n";

        // CSV FILE HANDLING

        if (csvFile.is_open())
        {
            csvFile
                << i - 1 << ","
                << src_ip << ","
                << ntohs(tcp->source_port) << ","
                << dst_ip << ","
                << ntohs(tcp->dest_port) << ","
                << ntohl(tcp->seq_num) << ","
                << ntohl(tcp->ack_num) << ","
                << tcp_hdr_len << ","
                << ntohs(tcp->window_size) << ","
                << ntohs(tcp->checksum) << ",";

            string flags = "";

            if (f & 0x20) flags += "URG ";
            if (f & 0x10) flags += "ACK ";
            if (f & 0x08) flags += "PSH ";
            if (f & 0x04) flags += "RST ";
            if (f & 0x02) flags += "SYN ";
            if (f & 0x01) flags += "FIN ";

            csvFile << "\"" << flags << "\"\n";

            csvFile.flush();
        }

        // RAW HEX TO FIELD MAPPING

        cout << "\n\n";
        cout << "============================================================\n";
        cout << "                 RAW HEX TO FIELD MAPPING                   \n";
        cout << "============================================================\n";

        cout << "\nSource IP (" << src_ip << ")\n";
        printHex(packet, eth_hdr_len + 12, 4);
        cout << "\n\n";

        cout << "Destination IP (" << dst_ip << ")\n";
        printHex(packet, eth_hdr_len + 16, 4);
        cout << "\n\n";

        cout << "Source Port (" << ntohs(tcp->source_port) << ")\n";
        printHex(packet, tcp_offset, 2);
        cout << "\n\n";

        cout << "Destination Port (" << ntohs(tcp->dest_port) << ")\n";
        printHex(packet, tcp_offset + 2, 2);
        cout << "\n\n";

        cout << "Sequence Number\n";
        printHex(packet, tcp_offset + 4, 4);
        cout << "\n\n";

        cout << "Acknowledgment Number\n";
        printHex(packet, tcp_offset + 8, 4);
        cout << "\n\n";

        cout << "TCP Flags\n";
        printHex(packet, tcp_offset + 13, 1);
        cout << "\n\n";

        cout << "============================================================\n";

        printHex(packet, header->caplen);
    }
};

class PacketSniffer
{
    pcap_t* handle_ = nullptr;

    TCPPacketAnalyzer analyzer_;

    CircularRingBuffer ring_buffer_{1024};

    thread worker_thread_;

    static void globalCallback(
        u_char* user,
        const struct pcap_pkthdr* header,
        const u_char* packet)
    {
        auto* sniffer_instance =
            reinterpret_cast<PacketSniffer*>(user);

        sniffer_instance->ring_buffer_.enqueue(header, packet);
    }

    void processPacketsLoop()
    {
        RawPacketItem item;

        while (ring_buffer_.dequeue(item))
        {
            analyzer_.analyze(
                &item.header, item.data.data());
        }
    }

public:

    ~PacketSniffer()
    {
        if (handle_)
        {
            pcap_breakloop(handle_);
            pcap_close(handle_);
            handle_ = nullptr;
        }

        ring_buffer_.setFinished();

        if (worker_thread_.joinable())
            worker_thread_.join();
    }

    string selectInterface()
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_if_t* devs = nullptr;

        if (pcap_findalldevs(&devs, errbuf) == -1 || !devs)
        {
            cerr << "Device lookup failed: "
                 << errbuf << endl;
            return "";
        }

        int count = 0;

        cout << "==================================================\n";
        cout << "           AVAILABLE NETWORK INTERFACES           \n";
        cout << "==================================================\n";

        for (pcap_if_t* d = devs;
             d != nullptr; d = d->next)
        {
            cout << "[" << ++count << "] " << d->name;

            if (d->description)
                cout << " (" << d->description << ")";

            cout << "\n";
        }

        if (count == 0)
        {
            cerr << "No network interfaces available.\n";
            pcap_freealldevs(devs);
            return "";
        }

        int choice = 0;

        cout << "\nEnter the interface number to listen on (1-"
             << count << "): ";

        cin >> choice;

        string selected_device = "";

        if (choice >= 1 && choice <= count)
        {
            pcap_if_t* target = devs;

            for (int j = 1; j < choice && target != nullptr; j++)
                target = target->next;

            if (target)
                selected_device = target->name;
        }
        else
        {
            cerr << "Invalid selection.\n";
        }

        pcap_freealldevs(devs);

        return selected_device;
    }

    void startSniffing(const string& device_name)
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        handle_ = pcap_open_live(
            device_name.c_str(), 65535, 1, 1000, errbuf);

        if (!handle_)
        {
            cerr << "Failed to open device: "
                 << errbuf << endl;
            return;
        }

        worker_thread_ =
            thread(&PacketSniffer::processPacketsLoop, this);

        cout << "\nListening for TCP packets on "
             << device_name << "...\n";

        pcap_loop(
            handle_, -1,
            PacketSniffer::globalCallback,
            reinterpret_cast<u_char*>(this));
    }
};

int main()
{
    PacketSniffer sniffer;

    string chosen_device = sniffer.selectInterface();

    if (!chosen_device.empty())
        sniffer.startSniffing(chosen_device);

    return 0;
}
