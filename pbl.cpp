#include <iostream>
#include <iomanip>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>

using namespace std;
int i=1;
#pragma pack(push, 1)
struct EthernetHeader 
{
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

struct IPHeader 
{
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
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
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};
#pragma pack(pop)

struct RawPacketItem {
    pcap_pkthdr header;
    vector<u_char> data;
};

class CircularRingBuffer {
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

public: CircularRingBuffer(size_t capacity = 1024) : capacity_(capacity), buffer_(capacity) {}

    bool push(const struct pcap_pkthdr* hdr, const u_char* packet) {
        unique_lock<mutex> lock(mutex_);
        if (count_ == capacity_)
            return false;
        buffer_[tail_].header = *hdr;
        buffer_[tail_].data.assign(packet, packet + hdr->caplen);
        tail_ = (tail_ + 1) % capacity_;
        count_++;
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }
    bool pop(RawPacketItem& item) {
        unique_lock<mutex> lock(mutex_);
        while (count_ == 0 && !finished_) {
            not_empty_.wait(lock);
        }

        if (count_ == 0 && finished_)
            return false;

        item = buffer_[head_];
        head_ = (head_ + 1) % capacity_;
        count_--;

        lock.unlock();
        not_full_.notify_one();
        return true;
    }

    void setFinished() {
        unique_lock<mutex> lock(mutex_);
        finished_ = true;
        lock.unlock();
        not_empty_.notify_all();
    }
};

class NetworkAnalyzer 
{
public: virtual ~NetworkAnalyzer() = default;

    void printHex(const u_char* packet, size_t start, size_t length) 
    {
        cout << "0x";
        for (size_t i = start; i < start + length; i++)
            cout << hex << setw(2) << setfill('0') << (int)packet[i] << " ";
        cout << dec;
    }

    void printHex(const u_char* packet, uint32_t total_length) 
    {
        cout << "\nFull Raw Hex Dump:\n";
        for (uint32_t i = 0; i < total_length; i++) 
        {
            cout << hex << setw(2) << setfill('0') << (int)packet[i] << " ";
            if ((i + 1) % 16 == 0 || i + 1 == total_length) cout << endl;
        }
        cout << dec;
    }
};

class TCPPacketAnalyzer : public NetworkAnalyzer 
{
public: void analyze(const struct pcap_pkthdr* header, const u_char* packet) 
    {
        if (header->caplen < sizeof(EthernetHeader))
            return;

        const auto* eth = reinterpret_cast<const EthernetHeader*>(packet);
        if (ntohs(eth->ether_type) != 0x0800) 
            return; 

        size_t eth_hdr_len = sizeof(EthernetHeader);
        if (header->caplen < eth_hdr_len + sizeof(IPHeader))
            return;

        const auto* ip = reinterpret_cast<const IPHeader*>(packet + eth_hdr_len);
        if (ip->protocol != 6) return;

        size_t ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
        size_t tcp_offset = eth_hdr_len + ip_hdr_len;
        if (header->caplen < tcp_offset + sizeof(TCPHeader))
            return;

        const auto* tcp = reinterpret_cast<const TCPHeader*>(packet + tcp_offset);
        size_t tcp_hdr_len = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->src_ip), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->dest_ip), dst_ip, INET_ADDRSTRLEN);
	
	cout << "\n" << i << "\n";
	i++;
        cout << "\n================ [ TCP PACKET CAPTURED ] ================\n";
        cout << "Source IP:Port      : " << src_ip << ":" << ntohs(tcp->source_port) << "\n";
        cout << "Destination IP:Port : " << dst_ip << ":" << ntohs(tcp->dest_port) << "\n";
        cout << "Seq / Ack Numbers   : " << ntohl(tcp->seq_num) << " / " << ntohl(tcp->ack_num) << "\n";
        cout << "Header Length       : " << tcp_hdr_len << " bytes\n";
        cout << "Window / Checksum   : " << ntohs(tcp->window_size) << " / 0x" << hex << ntohs(tcp->checksum) << dec << "\n";

        uint8_t f = tcp->flags;
        cout << "Flags               : [ "
             << (f & 0x20 ? "URG " : "") << (f & 0x10 ? "ACK " : "")
             << (f & 0x08 ? "PSH " : "") << (f & 0x04 ? "RST " : "")
             << (f & 0x02 ? "SYN " : "") << (f & 0x01 ? "FIN " : "") << "]\n";

        cout << "\n--- [ RAW HEX TO FIELD MAPPING ] ---\n";
        cout << "Source IP (" << src_ip << ")           -> Bytes [" 
             << eth_hdr_len + 12 << "-" << eth_hdr_len + 15 << "]: ";
        printHex(packet, eth_hdr_len + 12, 4);
        cout << "\n";

        cout << "Dest IP (" << dst_ip << ")             -> Bytes [" 
             << eth_hdr_len + 16 << "-" << eth_hdr_len + 19 << "]: ";
        printHex(packet, eth_hdr_len + 16, 4);
        cout << "\n";

        cout << "Source Port (" << ntohs(tcp->source_port) << ")          -> Bytes [" 
             << tcp_offset << "-" << tcp_offset + 1 << "]: ";
        printHex(packet, tcp_offset, 2);
        cout << "\n";

        cout << "Dest Port (" << ntohs(tcp->dest_port) << ")            -> Bytes [" 
             << tcp_offset + 2 << "-" << tcp_offset + 3 << "]: ";
        printHex(packet, tcp_offset + 2, 2);
        cout << "\n";

        cout << "Sequence Number             -> Bytes [" 
             << tcp_offset + 4 << "-" << tcp_offset + 7 << "]: ";
        printHex(packet, tcp_offset + 4, 4);
        cout << "\n";

        cout << "Ack Number                  -> Bytes [" 
             << tcp_offset + 8 << "-" << tcp_offset + 11 << "]: ";
        printHex(packet, tcp_offset + 8, 4);
        cout << "\n";

        cout << "TCP Flags Byte              -> Byte  [" 
             << tcp_offset + 13 << "]: ";
        printHex(packet, tcp_offset + 13, 1);
        cout << "\n";

        printHex(packet, header->caplen);
    }
};

class PacketSniffer 
{
    pcap_t* handle_ = nullptr;
    TCPPacketAnalyzer analyzer_;
    CircularRingBuffer ring_buffer_{1024};
    thread worker_thread_;

    static void globalCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
    {
        auto* sniffer_instance = reinterpret_cast<PacketSniffer*>(user);
        sniffer_instance->ring_buffer_.push(header, packet);
    }

    void processPacketsLoop() {
        RawPacketItem item;
        while (ring_buffer_.pop(item)) {
            analyzer_.analyze(&item.header, item.data.data());
        }
    }

public: ~PacketSniffer() 
    {
        if (handle_) {
            pcap_breakloop(handle_);
            pcap_close(handle_);
        }
        ring_buffer_.setFinished();
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    string selectInterface() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* devs;
        if (pcap_findalldevs(&devs, errbuf) == -1 || !devs) {
            cerr << "Device lookup failed: " << errbuf << endl;
            return "";
        }

        int count = 0;
        cout << "==================================================\n";
        cout << "           AVAILABLE NETWORK INTERFACES           \n";
        cout << "==================================================\n";
        for (pcap_if_t* d = devs; d != nullptr; d = d->next) {
            cout << "[" << ++count << "] " << d->name;
            if (d->description) {
                cout << " (" << d->description << ")";
            }
            cout << "\n";
        }

        if (count == 0) {
            cerr << "No network interfaces available.\n";
            pcap_freealldevs(devs);
            return "";
        }

        int choice = 0;
        cout << "\nEnter the interface number to listen on (1-" << count << "): ";
        cin >> choice;

        string selected_device = "";

        if (choice >= 1 && choice <= count) 
        {
            pcap_if_t* target = devs;
            for (int i = 1; i < choice && target != nullptr; ++i)
                target = target->next;
            if (target)
                selected_device = target->name;
        } 
        else
            cerr << "Invalid selection.\n";

        pcap_freealldevs(devs);
        return selected_device;
    }

    void startSniffing(const string& device_name) 
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle_ = pcap_open_live(device_name.c_str(), 65535, 1, 1000, errbuf);

        if (!handle_) 
        {
            cerr << "Failed to open device: " << errbuf << endl;
            return;
        }
        worker_thread_ = thread(&PacketSniffer::processPacketsLoop, this);

        cout << "\nListening for TCP packets on " << device_name << "...\n";
        pcap_loop(handle_, -1, PacketSniffer::globalCallback, reinterpret_cast<u_char*>(this));
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
