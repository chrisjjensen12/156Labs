#include <string.h>
#include <iostream>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <unistd.h>
#include <sstream>

using namespace std;
#define BUFFERLENGTH 32000 //max mtu for client

void do_server_processing(int sockfd, sockaddr *pcliaddr, socklen_t clilen){

    int n;
    int s;
    socklen_t len;
    char mesg[BUFFERLENGTH];

    string packet;

   for(;;){
        len = clilen;
        n = recvfrom(sockfd, mesg, BUFFERLENGTH, 0, pcliaddr, &len); //reads datagram
        if(n < 0){
            cerr << "recvfrom() failed.\n Exiting now.\n";
            exit(EXIT_FAILURE);
        }
        s = sendto(sockfd, mesg, n, 0, pcliaddr, len); //sends it back to sender
        if(s < 0){
            cerr << "sendto() failed.\n Exiting now.\n";
            exit(EXIT_FAILURE);
        }
        // cout << mesg;
    }

}

uint16_t get_port(int argc, char** argv){
    int port_num = 0;
    //check for correct amount of command line arguments
    if(argc > 2){ 
        cerr << "Too many command line arguments.\nFormat: ./myserver port_number\n";
        exit(EXIT_FAILURE);
    }

    string port_num_string = argv[1];
    //check if mtu is integer
    if (isdigit(port_num_string[0]))
    {
        port_num = stoi(port_num_string);
    }else{
        cerr << "Please use a correct port number. Exiting now.\n";
        exit(EXIT_FAILURE);
    }

    if(port_num <= 1024){
        cerr << "Port number should be greater than 1024, and less than 65536\n";
        exit(EXIT_FAILURE);
    }else if(port_num >= 65536){
        cerr << "Port number should be greater than 1024, and less than 65536\n";
        exit(EXIT_FAILURE);
    }

    return port_num;
}

int main(int argc, char** argv)
{

    uint16_t port_num = get_port(argc, argv);

    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0); //create a udp socket using SOCK_DGRAM
    if(sockfd < 0){
        cerr << "socket() failed. Exiting now.\n";
        exit(EXIT_FAILURE);
    }
    bzero(&servaddr, sizeof(servaddr)); //zero out server addr

    //set up server struct info
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port_num); //converts from MY local byte order to network standard


    if(bind(sockfd, (sockaddr *) &servaddr, sizeof(servaddr)) < 0){
        cerr << "bind() failed. Exiting now.\n";
        exit(EXIT_FAILURE);
    }


    do_server_processing(sockfd, (sockaddr *) &cliaddr, sizeof(cliaddr));


    return 0;
}