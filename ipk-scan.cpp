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

int getIp(string *target, struct addrinfo* addr) {

    struct addrinfo hints;
    memset(&hints, 0 , sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_protocol = 0;
    int addinfoRet = getaddrinfo(&(*target->c_str()), NULL, &hints, &addr);
    if (addinfoRet != 0) {
        return 1;
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

    //addrinfo struct for TODO LICENSE COMMENT FROM WIKIPEDIA getaddrinfo
    struct addrinfo *destination, current;
    struct sockaddr *destAddr;

    regex ipv4pattern ("^(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})$");
    if(!regex_match(target, ipv4pattern)) {
        int ipRet = getIp(&target, destination);
        if (ipRet == 1) {
            cerr << "Failed to obtain address from specified domain name." << endl;
            return 1;
        }
    }

    destAddr = destination->ai_addr;

    cout << inet_ntoa(((struct sockaddr_in *)destAddr)->sin_addr) << endl;

    return 0;
}
