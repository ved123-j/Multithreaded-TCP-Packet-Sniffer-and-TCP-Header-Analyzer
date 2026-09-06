#include <iostream>
#include <iomanip>
#include <pcap.h>
using namespace std;
void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
{
    cout << "\nPacket Captured: " << header->len << " bytes" << endl;
    for (int i=0;i<header->caplen;i++) 
	{
        cout<< hex << setw(2)<< setfill('0') <<(int)packet[i] << " ";
        if ((i + 1) % 16 == 0 || i + 1 == header->caplen)
            cout << endl;
        }
}
int main()
{
    char err_msg[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;

    if (pcap_findalldevs(&interfaces, err_msg) == -1) 
    {
        cerr << "Error finding devices: " << err_msg << endl;
        return 1;
    }
    if (interfaces == nullptr)
    {
        cerr << "No network interfaces found." << endl;
        return 1;
    }
    string interface = interfaces->name;
    cout << "Selected Interface: " << interface << endl;
    pcap_t* handle = pcap_open_live(interface.c_str(), 65535, 1, 1000, err_msg);
    if (handle == nullptr) 
    {
        cerr << "Could not open device " << interface << ": " << err_msg << endl;
        pcap_freealldevs(interfaces);
        return 1;
    }

    pcap_freealldevs(interfaces);
    cout << "Listening for packets..." << endl;
    pcap_loop(handle, -1, packetHandler, nullptr);
    pcap_close(handle);
    return 0;
}
