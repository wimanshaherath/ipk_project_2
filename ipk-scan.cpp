#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <regex>
#include <getopt.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <signal.h>
using namespace std;

struct tcpPhdr { //custom tcp pseudoheader
    u_int32_t source;
    u_int32_t dest;
    u_int8_t zeros=0;
    u_int8_t protocol;
    u_int16_t tcplen;
};

pcap_t *handle; //handle for packet capture

/**
 * Function that parses and checks validity of arguments, then fills the respective containers.
 * @param argc number of input arguments
 * @param argv array of char arrays, containing input arguments
 * @param argFlags auxiliary array to keep track of which options were used
 * @param interface string for interface specified by user
 * @param pu_ports vector of ports for udp scanning
 * @param pt_ports vector of ports for tcp scanning
 * @param target
 * @return 0 if input arguments are correct, 1 if an error is encountered
 */
int parseOpts(int argc, char **argv, int *argFlags, string *interface, vector<int> *pu_ports, vector<int> *pt_ports, string* target) {
    char opt;
    static struct option long_opts[] = {  //TODO LICENSE COMMENT FROM GETOPT MAN PAGE
            {"i", required_argument, 0, 'i'},
            {"pu", required_argument, 0, 'u'},
            {"pt", required_argument, 0, 't'},
            {0, 0, 0, 0}
    };
    int option_index = 0;
    while ((opt = getopt_long_only(argc, argv, "i:u:t:", long_opts, &option_index)) != -1) {
        switch (opt) {
            case 'i':{
                    argFlags[0] = 1;
                    *interface = string(optarg);
                }
                break;
            case 'u': {
                    argFlags[1] = 1;
                    regex pattern ("([1-9][0-9]{0,4})(?:,([1-9][0-9]{0,4}))*");
                    regex pattern2 ("^([1-9][0-9]{0,4})-([1-9][0-9]{0,4})$");
                    cmatch cm;
                    if (regex_match(optarg, cm, pattern)) { //22,23...
                        string toSplit = string(cm[0]);
                        int portNum;
                        size_t last = 0; //TODO LICENSE CODE FROM STACKOVERFLOW parse a string in c++ using string delimiter
                        size_t next = 0;
                        while ((next = toSplit.find(',', last)) != string::npos) {
                            portNum = stoi(toSplit.substr(last, next - last));
                            last = next + 1;
                            if (portNum > 65535) {
                                cerr << "Port number must be in range 1-65535." << endl;
                                return 1;
                            }
                            pu_ports->push_back(portNum);
                        }
                        portNum = stoi(toSplit.substr(last));
                        if (portNum > 65535) {
                            cerr << "Port number must be in range 1-65535." << endl;
                            return 1;
                        }
                        pu_ports->push_back(portNum);
                    } else if (regex_match(optarg, cm, pattern2)) { //22-23
                        int from = stoi(string(cm[1]));
                        int to = stoi(string(cm[2]));
                        if (from > to) {
                            cerr << "Invalid port range <a;b>, a must be lower or equal to b." << endl;
                            return 1;
                        }
                        if (to > 65535) {
                            cerr << "Port number must be in range 1-65535." << endl;
                            return 1;
                        }
                        for (int i = from; i <= to; i++) {
                            pu_ports->push_back(i);
                        }
                    } else {
                        cerr << "Invalid argument of option -pu." << endl;
                        return 1;
                    }
                }
                break;
            case 't': {
                    argFlags[2] = 1;
                    regex pattern("^([1-9][0-9]{0,4})(?:,([1-9][0-9]{0,4}))*$");
                    regex pattern2("^([1-9][0-9]{0,4})-([1-9][0-9]{0,4})$");
                    cmatch cm;
                    if (regex_match(optarg, cm, pattern)) { //22,23...
                        string toSplit = string(cm[0]);
                        int portNum;
                        size_t last = 0; //TODO LICENSE CODE FROM STACKOVERFLOW parse a string in c++ using string delimiter
                        size_t next = 0;
                        while ((next = toSplit.find(',', last)) != string::npos) {
                            portNum = stoi(toSplit.substr(last, next - last));
                            last = next + 1;
                            if (portNum > 65535) {
                                cerr << "Port number must be in range 1-65535." << endl;
                                return 1;
                            }
                            pt_ports->push_back(portNum);
                        }
                        portNum = stoi(toSplit.substr(last));
                        if (portNum > 65535) {
                            cerr << "Port number must be in range 1-65535." << endl;
                            return 1;
                        }
                        pt_ports->push_back(portNum);
                    } else if (regex_match(optarg, cm, pattern2)) { //22-23
                        int from = stoi(string(cm[1]));
                        int to = stoi(string(cm[2]));
                        if (from > to) {
                            cerr << "Invalid port range <a;b>, a must be lower or equal to b." << endl;
                            return 1;
                        }
                        if (to > 65535) {
                            cerr << "Port number must be in range 1-65535." << endl;
                            return 1;
                        }
                        for (int i = from; i <= to; i++) {
                            pt_ports->push_back(i);
                        }
                    } else {
                        cerr << "Invalid argument of option -pu." << endl;
                        return 1;
                    }
            }
                break;
            default:
                break;
        }
    }
    if (optind >= argc) { //domain name or ip missing
        cerr << "Domain name or ip address not specified." << endl;
        return 1;
    } else {
        *target = string(argv[optind]);
    }
    return 0;
}

unsigned short csum(unsigned short *buf, int len) { //TODO LICENSE COMMENT TENOUK module43a
    unsigned long sum;
    for (sum = 0; len > 0; len--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

void tcp_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    //TODO LICENSE COMMENT DEVDUNGEON using libpcap in C
    struct ether_header *ethhdr = (struct ether_header *) packet;
    struct ip *ip = (struct ip *) (packet + sizeof(struct ether_header));
    int ip_len = ip->ip_hl*4;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ether_header) + ip_len);
    
    if (tcp->th_flags == (TH_RST + TH_ACK)) { //constant from netinet/tcp.h
        cout << "closed" << endl;
    } else {
        cout << "open" << endl;
    }

    return;
}

void udp_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *ethhdr = (struct ether_header *) packet;
    struct ip *ip = (struct ip *) (packet + sizeof(struct ether_header));
    int ip_len = ip->ip_hl*4;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof(struct ether_header) + ip_len);
    
    if (icmp->type == ICMP_DEST_UNREACH) { //constant from netinet/ip_icmp.h
        cout << "closed" << endl;
    } else {
        cout << "open" << endl;
    }

    return;
}

void timeout_handler(int sig) {
    pcap_breakloop(handle);
}

int main(int argc, char **argv) {
    //containers for command line arguments
    int argFlags[3] = {0}; //0 = i, 1 = pu, 2 = pt
    string interface;
    vector<int> pu_ports;
    vector<int> pt_ports;
    string target;

    //parse command line arguments
    int parseRet = parseOpts(argc, argv, argFlags, &interface, &pu_ports, &pt_ports, &target);
    if (parseRet == 1) {
        return 1;
    }

    //check for invalid combination of arguments
    if (argFlags[1] == 0 && argFlags[2] == 0) {
        cerr << "At least one of options -pu or -pt must be specified." << endl;
        return 1;
    }

    //addrinfo struct for TODO LICENSE COMMENT FROM MAN PAGES getaddrinfo
    struct addrinfo *destination, hints;
    struct sockaddr_in *destAddr, *sourceAddr;

    //get ip address from domain name
    regex ipv4pattern ("^(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})$");
    if(!regex_match(target, ipv4pattern)) {
        memset(&hints, 0 , sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = 0;
        hints.ai_protocol = 0;
        int addrInfoRet = getaddrinfo(&(*target.c_str()), NULL, &hints, &destination);
        if (addrInfoRet == 1) {
            cerr << "Failed to obtain address from specified domain name." << endl;
            return 1;
        }
        destAddr = (struct sockaddr_in *)destination->ai_addr;
    } else {
        destAddr = (struct sockaddr_in *) malloc(sizeof(*destAddr));
        inet_aton(target.c_str(), &(destAddr->sin_addr));
    }

    //cout << inet_ntoa(destAddr->sin_addr) << endl;

    //interface address
    struct ifaddrs *interfaces, *ifs, *source = NULL;
    int ifAddrRet = getifaddrs(&interfaces);
    if (ifAddrRet == 1) {
        cerr << "Failed to obtain list of interfaces." << endl;
        if(destination != NULL) {
            free(destination);
        }
        return 1;
    }

    ifs = interfaces;
    //TODO LICENSE COMENT FROM MAN PAGES getifaddrs
    if (argFlags[0] == 1) { //interface name specified by user
        while(ifs) {
            if (ifs->ifa_addr == NULL) {
                ifs = ifs->ifa_next;
                continue;
            }
            if (string(ifs->ifa_name) == interface && ifs->ifa_addr->sa_family == AF_INET) {
                source = ifs;
                break;
            }
            ifs = ifs->ifa_next;
        }
        if (source == NULL) {
            cerr << "Could not find specified interface." << endl;
            if (destination != NULL) {
                freeaddrinfo(destination);
            }
            freeifaddrs(interfaces);
            return 1;
        }
    } else { //no interface specified by user, find first nonloopback interface
        while(ifs) {
            if (ifs->ifa_addr == NULL) {
                ifs = ifs->ifa_next;
                continue;
            }
            if ((ifs->ifa_addr->sa_family) == AF_INET && !(ifs->ifa_flags & IFF_LOOPBACK)) {
                source = ifs;
                interface = string(ifs->ifa_name);
                break;
            }
            ifs = ifs->ifa_next;
        }
        if (source == NULL) {
            cerr << "Could not find a non loopback interface." << endl;
            if(destination != NULL) {
                freeaddrinfo(destination);
            }
            freeifaddrs(interfaces);
            return 1;
        }
    }
    
    sourceAddr = (struct sockaddr_in *)source->ifa_addr;

    //cout << inet_ntoa(sourceAddr->sin_addr) << endl;
    cout << "Interesting ports on " + target + ":" << endl;
    cout << "PORT        STATE" << endl;
    //tcp
    if (argFlags[2] == 1) { //TODO LICENSE COMMENT FROM TENOUK module43a
        int one = 1;
        const int *val = &one;
               
        int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            cerr << "Error opening socket." << endl;
            return 1;
        }

        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
            cerr << "Error setting socket options." << endl;
            return 1;
        }
        //initialize pcap handle TODO LICENSE COMMENT FROM DEVDUNGEON using libpcap in c
        char pcap_err_buffer[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;

        int repeatFiltered = 0;

        //header size
        char buffer[8192];
        char buffer2[8192];
        memset(buffer, 0, 8192);
        memset(buffer2, 0, 8192);

        for (unsigned int i = 0; i < pt_ports.size(); i++) {
            if (repeatFiltered == 0) { //print ports only once
                cout << to_string(pt_ports[i]) + "/tcp      ";
            }
            //set pcap
            handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, pcap_err_buffer);
            if (handle == NULL) {
                cerr << "Could not create pcap handle." << endl;
                return 1;
            }
            string pcap_filter = "tcp and src port " + to_string(pt_ports[i]) + " and dst port 50000";
            int pcompileRet = pcap_compile(handle, &filter, pcap_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN);
            if (pcompileRet == -1) {
                cerr << "Could not compile filter string." << endl;
                return 1;
            }

            int psetfilRet = pcap_setfilter(handle, &filter);
            if (psetfilRet == -1) {
                cerr << "Could not set pcap filter." << endl;
                return 1;
            }

            //address family
            sourceAddr->sin_family = AF_INET;
            destAddr->sin_family = AF_INET;

            //ports
            sourceAddr->sin_port = htons(50000);
            destAddr->sin_port = htons(pt_ports[i]);

            //fill pseudotcp header
            struct tcpPhdr *tcpPh = (struct tcpPhdr *) buffer;
            tcpPh->source = inet_addr(inet_ntoa(sourceAddr->sin_addr));
            tcpPh->dest = inet_addr(inet_ntoa(destAddr->sin_addr));
            tcpPh->protocol = 6;
            tcpPh->tcplen = htons(sizeof(struct tcphdr));

            //create and fill tcp header
            struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof(struct tcpPhdr));
            tcph->th_off = 5;
            tcph->th_sport = htons(50000);
            tcph->th_dport = htons(pt_ports[i]);
            tcph->th_seq = htonl(1);
            tcph->th_ack = 0;
            tcph->th_win = htons(32767);
            tcph->th_sum = 0;
            tcph->th_urp = 0;
            tcph->th_flags = TH_SYN;

            //calculate tcp checksum
            tcph->th_sum = csum((unsigned short *) buffer, (sizeof(struct tcpPhdr) + sizeof(struct tcphdr)));

            //create and fill ip header
            struct ip *iph = (struct ip *) buffer2;
            iph->ip_hl = 5;
            iph->ip_v = 4;
            iph->ip_tos = 16;
            iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
            iph->ip_id = htons(54321);
            iph->ip_off = 0;
            iph->ip_ttl = 64;
            iph->ip_p = 6;
            iph->ip_sum = 0;
            iph->ip_src = sourceAddr->sin_addr;
            iph->ip_dst = destAddr->sin_addr;

            memcpy(buffer2 + sizeof(struct ip), buffer + sizeof(struct tcpPhdr), sizeof(struct tcphdr));

            //calculate ip sum
            iph->ip_sum = csum((unsigned short *) buffer2, (sizeof(struct ip) + sizeof(struct tcphdr)));
            
            if (sendto(sock, buffer2, iph->ip_len, 0, (struct sockaddr *)destAddr, sizeof(struct sockaddr_in)) < 0) {
                perror("sendto() error");
                return 1;
            }

            //capture and process packetr;
            if (repeatFiltered == 0) { //LICENSE COMMENT listening using pcap with timeout
                alarm(2);
                signal(SIGALRM, timeout_handler);
                if (pcap_loop(handle, 1, tcp_packet_handler, NULL) < 0) {
                    repeatFiltered = 1;
                    i -= 1;
                } 
            } else {
                alarm(2);
                signal(SIGALRM, timeout_handler);
                if (pcap_loop(handle, 1, tcp_packet_handler, NULL) < 0) {
                    cout << "filtered" << endl;
                    repeatFiltered = 0;
                }
            }
            pcap_freecode(&filter);
        }
        pcap_close(handle);
    }
    if (argFlags[1] == 1) {
        int one = 1;
        const int *val = &one;
               
        int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) {
            cerr << "Error opening socket." << endl;
            return 1;
        }

        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
            cerr << "Error setting socket options." << endl;
            return 1;
        }

        //initialize pcap handle TODO LICENSE COMMENT FROM DEVDUNGEON using libpcap in c
        char pcap_err_buffer[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;

        int repeatFiltered = 0;

        //header size
        char buffer[8192];
        //char buffer2[8192];
        memset(buffer, 0, 8192);
        //memset(buffer2, 0, 8192);

        for (int i = 0; i < pu_ports.size(); i++) {
            if (repeatFiltered == 0) { //print ports only once
                cout << to_string(pu_ports[i]) + "/udp      ";
            }
            //set pcap
            handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, pcap_err_buffer);
            if (handle == NULL) {
                cerr << "Could not create pcap handle." << endl;
                return 1;
            }
            string pcap_filter = "udp and src port " + to_string(pu_ports[i]) + " and dst port 50000";
            int pcompileRet = pcap_compile(handle, &filter, pcap_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN);
            if (pcompileRet == -1) {
                cerr << "Could not compile filter string." << endl;
                return 1;
            }

            //address family
            sourceAddr->sin_family = AF_INET;
            destAddr->sin_family = AF_INET;

            //ports
            sourceAddr->sin_port = htons(50000);
            destAddr->sin_port = htons(pu_ports[i]);

            //create and fill ip header
            struct ip *iph = (struct ip *) buffer;
            iph->ip_hl = 5;
            iph->ip_v = 4;
            iph->ip_tos = 16;
            iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr);
            iph->ip_id = htons(54321);
            iph->ip_off = 0;
            iph->ip_ttl = 64;
            iph->ip_p = 17;
            iph->ip_sum = 0;
            iph->ip_src = sourceAddr->sin_addr;
            iph->ip_dst = destAddr->sin_addr;

            //create and fill udp header
            struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct ip));
            udph->uh_sport = htons(50000);
            udph->uh_dport = htons(pu_ports[i]);
            udph->uh_ulen = htons(sizeof(struct udphdr));
            udph->uh_sum = 0;

            iph->ip_sum = csum((unsigned short *) buffer, (sizeof(struct ip) + sizeof(struct udphdr)));
        
            if (sendto(sock, buffer, iph->ip_len, 0, (struct sockaddr *)destAddr, sizeof(struct sockaddr_in)) < 0) {
                perror("sendto() error");
                return 1;
            }

            //fix packet capture
            pcap_loop(handle, 1, udp_packet_handler, NULL);
            pcap_freecode(&filter);
        }
        pcap_close(handle);
    }

    if(regex_match(target, ipv4pattern)) {
        free(destAddr);
    }

    freeaddrinfo(destination);
    if (interfaces != NULL) {
        freeifaddrs(interfaces);
    }
    return 0;
}
