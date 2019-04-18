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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
using namespace std;

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
                            pu_ports->push_back(i);
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
    struct sockaddr *destAddr, *sourceAddr;

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
        destAddr = destination->ai_addr;
    }

    //cout << inet_ntoa(((struct sockaddr_in *)destAddr)->sin_addr) << endl;

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
    sourceAddr = source->ifa_addr;

    //cout << inet_ntoa(((struct sockaddr_in *)sourceAddr)->sin_addr) << endl;

    freeaddrinfo(destination);
    if (interfaces != NULL) {
        freeifaddrs(interfaces);
    }
    return 0;
}
