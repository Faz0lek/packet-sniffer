/**
 * @file main.cpp
 * @author Martin Kostelník (xkoste12@stud.fit.vutbr.cz)
 * @brief IPK - Project 2 - Packet sniffer
 * @version 1.0
 * @date 2020-05-03
 * 
 */

#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <string>
#include <pcap/pcap.h>
#include <time.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

const int RC_FAILURE = 1;
const int RC_SUCCESS = 0;

const u_char UDP_TYPE = 17;
const u_char TCP_TYPE = 6;

/**
 * @brief Struct which holds data about program arguments
 * 
 */
struct args
{
    bool        iFlag;      // interface argument
    std::string interface;  // interface
    bool        pFlag;      // port argument
    int         port;       // port
    bool        tcpFlag;    // --tcp or -t argument
    bool        udpFlag;    // --udp or -u argument
    int         n;          // amount of packets to catch

    args() : iFlag(false), interface(""), pFlag(false), port(-1), tcpFlag(false), udpFlag(false), n(1) {}

    /**
     * @brief DEBUG ONLY, prints entered arguments to stderr
     * 
     */
    void printArgs()
    {
        std::cerr << "iflag: " << this->iFlag << "\n" <<
                     "interface: " << this->interface << "\n" <<
                     "n: " << this->n << "\n" <<
                     "pflag: " << this->pFlag << "\n" <<
                     "port: " << this->port <<  "\n" <<
                     "tcpflag: " << this->tcpFlag << "\n" <<
                     "udpflag: " << this->udpFlag << "\n";
    }
};

/**
 * @brief Struct which holds misc data about packet
 * 
 */
struct packetHead
{
    std::string timeStamp;          // time when the packet was received
    std::string sourceAddress;      // source domain name (or IPv4 address)
    std::string destinationAddress; // destination domain name (or IPV4 address)
    std::string sourcePort;         // source port
    std::string destinationPort;    // destination port
};

/**
 * @brief Prints help about running the program
 * 
 */
void printHelp()
{
    std::cout << "IPK Packet sniffer - displays packets filtered by arguments\n";
    std::cout << "Usage:\n./proj2 -i interface [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n\n";
    std::cout << "-i interface - specifies interface to sniff at\n";
    std::cout << "-p port - specifies the port to sniff at\n";
    std::cout << "-t --tcp - show only TCP packets\n";
    std::cout << "-u --udp - show only UDP packets\n";
    std::cout << "-n num show 'num' amount of packets\n";
}

/**
 * @brief This function parses command line arguments
 * 
 * @param argc Argument count
 * @param argv Arguments
 * @return args Returns struct containing parsed arguments
 */
args parseArgs(int argc, char* argv[])
{
    args arguments;

    const char* const shortOps = ":i:p:n:tu;";
    const struct option longOpts[] = {
        {"tcp", no_argument, nullptr, 't'},
        {"udp", no_argument, nullptr, 'u'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt = 0;
    while ((opt = getopt_long(argc, argv, shortOps, longOpts, nullptr)) != EOF)
    {
        switch (opt)
        {
            case 'i':
                arguments.iFlag = true;
                arguments.interface = optarg;
                break;
            case 'p':
                arguments.pFlag = true;
                try
                {
                    arguments.port = std::stoi(optarg);
                }
                catch (const std::invalid_argument& ia)
                {
                    printHelp();
                    exit(RC_FAILURE);
                }
                catch (const std::out_of_range& oor)
                {
                    printHelp();
                    exit(RC_FAILURE);
                }
                break;
            case 'n':
                try
                {
                    arguments.n = std::stoi(optarg);
                    if (arguments.n <= 0)
                    {
                        printHelp();
                        exit(RC_FAILURE);
                    }
                }
                catch (const std::invalid_argument& ia)
                {
                    printHelp();
                    exit(RC_FAILURE);
                }
                catch (const std::out_of_range& oor)
                {
                    printHelp();
                    exit(RC_FAILURE);
                }
                break;
            case 't':
                arguments.tcpFlag = true;
                break;
            case 'u':
                arguments.udpFlag = true;
                break;
            case 'h':
                printHelp();
                exit(RC_SUCCESS);
                break;
            case '?':
            default:
                printHelp();
                exit(RC_FAILURE);
                break;
        }
    }

    // Check combination of --udp and --tcp
    if (arguments.tcpFlag && arguments.udpFlag)
    {
        printHelp();
        exit(RC_FAILURE);
    }

    return arguments;
}

/**
 * @brief Thif function prints interfaces available for packet sniffing
 * 
 */
void printInterfaces()
{
        char error[PCAP_ERRBUF_SIZE];
        pcap_if_t* interfaces;

        if (pcap_findalldevs(&interfaces, error) == PCAP_ERROR)
        {
            std::cerr << __LINE__ << ": " << error << "\n";
            exit(RC_FAILURE);
        }
        else
        {
            for (pcap_if_t* interface = interfaces; interface; interface = interface->next)
            {
                std::cout << interface->name << "\n";
            }
        }
}

/**
 * @brief This function constucts a correct libpcap filter expression based on the program arguments
 * 
 * @param arguments Arguments
 * @return std::string Returns the filter expression
 */
std::string constructFilter(const args& arguments)
{
    std::string filterExpression = "ip"; // capture IPv4 packets only

    if (arguments.tcpFlag)
    { 
        filterExpression += " and tcp"; // add TCP filter
    }
    else if (arguments.udpFlag)
    {
        filterExpression += " and udp"; // add UDP filter
    }

    if (arguments.port != -1)
    {
        filterExpression += " and port " + std::to_string(arguments.port); // add port filter
    }

    return filterExpression;
}

/**
 * @brief This function creates and returns misc packet information such as time, source address etc.
 * 
 * @param type UDP or TCP
 * @param header Packet header
 * @param iph IP Header
 * @param packet Packet
 * @return packetHead Returns packetHead struct containing the data
 */
packetHead getHead(const int type,const struct pcap_pkthdr* const header, const struct iphdr* const iph, const u_char* const packet)
{
    packetHead h;

    // Find source and destination addresses
    struct sockaddr_in source, destination;
    memset(&source, 0, sizeof(source));
    memset(&destination, 0, sizeof(destination));

    source.sin_addr.s_addr = iph->saddr;
    destination.sin_addr.s_addr = iph->daddr;

    h.sourceAddress = inet_ntoa(source.sin_addr);
    h.destinationAddress = inet_ntoa(destination.sin_addr);

    // Try to find source and destination domain name
    const struct hostent* const sourceName = gethostbyaddr(&iph->saddr, sizeof(iph->saddr), AF_INET);
    const struct hostent* const destName = gethostbyaddr(&iph->daddr, sizeof(iph->daddr), AF_INET);

    if (sourceName !=  NULL)
    {
        h.sourceAddress = sourceName->h_name;
    }
    if (destName != NULL)
    {
        h.destinationAddress = destName->h_name;
    }

    // Find source and destination ports
    if (type == UDP_TYPE)
    {
        struct udphdr* udph = (struct udphdr*)(packet + (iph->ihl * 4) + sizeof(struct ethhdr));
        h.sourcePort = std::to_string(ntohs(udph->source));
        h.destinationPort = std::to_string(ntohs(udph->dest));
    }  
    else if (type == TCP_TYPE)
    {
        struct tcphdr* tcph = (struct tcphdr*)(packet + (iph->ihl * 4) + sizeof(struct ethhdr));
        h.sourcePort = std::to_string(ntohs(tcph->source));
        h.destinationPort = std::to_string(ntohs(tcph->dest));
    }
    
    // Find timestamp
    time_t time_sec = header->ts.tv_sec;
    const struct tm* const time = localtime(&time_sec);
    h.timeStamp = std::to_string(time->tm_hour) + ":" + (std::to_string(time->tm_min).length() == 1 ? "0" + std::to_string(time->tm_min) : std::to_string(time->tm_min)) + ":" + std::to_string(time->tm_sec) + "." + std::to_string(header->ts.tv_usec);

    return h;
}

/**
 * @brief This function prints misc data about packet
 * 
 * @param h Packet head
 */
void printHead(const packetHead h)
{
    std::cout << h.timeStamp << " " << h.sourceAddress << " : " << h.sourcePort << " > " << h.destinationAddress << " : " << h.destinationPort << "\n\n";
}

/**
 * @brief This function prints one line of packet data
 *        To achieve a nice formatting of packet and proper functionality, this function is inspired by a code
 *        from: https://simplestcodings.blogspot.com/2010/10/create-your-own-packet-sniffer-in-c.html?fbclid=IwAR1TSz9u8KcyX1ryH1xHU-N3iXLAM8b4kVVdCkonE6hR6TSa7J4avTKmrhg
 * 
 * @param data Packet data
 * @param len Line length
 * @param offset Line offset
 */
void printLine(const u_char* const data, const size_t len, const size_t offset)
{
    // print data offset
    std::stringstream s;
    s << "0x" << std::setfill('0') << std::setw(4) << std::hex << offset;
    std::cout << s.str() << " ";

    const u_char* d = data;

    // print HEX data
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x ", *d);
        d++;

        if (i == 7)
        {
            std::cout << " ";
        }
    }

    // formatting for easier reading
    if (len < 8)
    {
        std::cout << " ";
    }

    if (len < 16)
    {
        for (int i = 0; i < 16 - len; i++)
        {
            std::cout << "   ";
        }
    }
    std::cout << "  ";

    // print ASCII data
    d = data;
    for (size_t i = 0; i < len; i++)
    {
        if (isprint(*d))
        {
            std::cout << *d;
        }
        else
        {
            std::cout << ".";
        }

        d++;
    }

    std::cout << "\n";
}

/**
 * @brief This function handles printing of entire packet
 * 
 * @param packet Packet
 * @param size Packet size
 */
void printPacket(const u_char* const packet, const size_t size)
{
    const size_t BYTES_PER_LINE = 16; // WIDTH
    
    size_t offset = 0,      // line offset
           remData = size,  // remaining data to print
           l = 0;           // length

    const u_char* data = packet;

    if (size == 0) // packet empty
    {
        return;
    }

    // packet fits on one line
    if (size <= BYTES_PER_LINE)
    {
        printLine(data, size, offset);
        std::cout << "\n\n";
        return;
    }

    // packet does not fit on one line
    while (true)
    {
        l = BYTES_PER_LINE % remData;
        
        printLine(data, l, offset);
        
        remData -= l;
        data += l;
        offset += BYTES_PER_LINE;
        
        // when remaining data is less than line width, print the remains and exit the loop
        if (remData <= BYTES_PER_LINE)
        {
            printLine(data, remData, offset);
            break;
        }
    }

    std::cout << "\n\n";
}

/**
 * @brief Callback function for packet processing
 * 
 * @param args Useless here
 * @param header Packet header
 * @param packet Packet data
 */
void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    const size_t size = header->len;
    const struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    const size_t iph_len = iph->ihl * 4;
    
    if (iph->protocol == TCP_TYPE)
    {
        const struct tcphdr* const tcph = (struct tcphdr*)(packet + iph_len + sizeof(struct ethhdr));
        const size_t h_len = sizeof(struct ethhdr) + iph_len + sizeof(tcph);

        printHead(getHead(TCP_TYPE, header, iph, packet));
        printPacket(packet + h_len, size - h_len);
    }
    else if (iph->protocol == UDP_TYPE)
    {
        const struct udphdr* const udph = (struct udphdr*)(packet + iph_len + sizeof(struct ethhdr));
        const size_t h_len = sizeof(struct ethhdr) + iph_len + sizeof(udph);

        printHead(getHead(UDP_TYPE, header, iph, packet));
        printPacket(packet + h_len, size - h_len);
    }
}

/**
 * @brief This function runs the sniffer
 * 
 * @param arguments program arguments
 */
void runSniffer(const args& arguments)
{
    char error[PCAP_ERRBUF_SIZE];

    const std::string filterExpression = constructFilter(arguments);
    struct bpf_program compiledFilter;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    pcap_t* handle;

    if (pcap_lookupnet(arguments.interface.c_str(), &net, &mask, error) == PCAP_ERROR)
    {
        net = mask = 0;
    }
    if ((handle = pcap_open_live(arguments.interface.c_str(), BUFSIZ, 1, 1000, error)) == nullptr)
    {
        std::cerr << __LINE__ << ": " << error << "\n";
        exit(RC_FAILURE);
    }
    if (pcap_compile(handle, &compiledFilter, filterExpression.c_str(), 0, net) == PCAP_ERROR)
    {
        std::cerr << __LINE__ << ": " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        exit(RC_FAILURE);
    }
    if (pcap_setfilter(handle, &compiledFilter) == PCAP_ERROR)
    {
        std::cerr << __LINE__ << ": " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        pcap_freecode(&compiledFilter);
        exit(RC_FAILURE);
    }
    if (pcap_loop(handle, arguments.n, processPacket, nullptr) == PCAP_ERROR)
    {
        std::cerr << __LINE__ << ": " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        pcap_freecode(&compiledFilter);
        exit(RC_FAILURE);
    }

    pcap_freecode(&compiledFilter);
    pcap_close(handle);
}

/**
 * @brief Entry point of application
 * 
 * @param argc Argument count
 * @param argv Arguments
 * @return int Return code
 */
int main(int argc, char* argv[])
{
    const args arguments = parseArgs(argc, argv);

    if (arguments.iFlag)
    {
        runSniffer(arguments);
    }
    else
    {
        printInterfaces();
    }
    
    return RC_SUCCESS;
}
