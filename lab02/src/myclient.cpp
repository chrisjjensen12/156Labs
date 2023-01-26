#include <string.h>
#include <iostream>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;
#define BUFFERLENGTH 4096

struct server_info {
    string server_IP;
    uint16_t server_port;
    uint16_t mtu;
    string in_file_path;
    string out_file_path;
};

void error_and_exit(string print_error){

    int errnum;
    errnum = errno;

    if(errnum != 0){
        cerr << print_error << "\n" << "errno: " << errnum << "\n";
    }else{
        cerr << print_error << "\n";
    }

    exit(EXIT_FAILURE); 
}

void print_info(server_info server_info1){
    cout << "Server IP: " << server_info1.server_IP << "\n";
    cout << "Server Port: " << server_info1.server_port << "\n";
    cout << "MTU: " << server_info1.mtu << "\n";
    cout << "in file path: " << server_info1.in_file_path << "\n";
    cout << "out file path: " << server_info1.out_file_path << "\n";
    return;
}

server_info get_commandline_args(int argc, char** argv){

    server_info info;

    if(argc != 6){
        cerr << "Incorrect number of command line arguments.\nFormat: ./myclient server_ip server_port mtu in_file_path out_file_path\n";
        exit(EXIT_FAILURE);
    }

    //assign string to server_ip. Will throw error later if this is incorrect
    info.server_IP = argv[1];

    //check if port is integer
    char* p;
    long converted_port = strtol(argv[2], &p, 10);
    if (*p) {
        error_and_exit("Please use a numerical port number");
    }
    else {
        if(converted_port > 65536){ //check if port is not greater than 2^16
            error_and_exit("Port number should not be larger than 2^16");
        }
        info.server_port = converted_port;
    }

    //check if mtu is integer
    char* g;
    long converted_mtu = strtol(argv[3], &g, 10);
    if (*g) {
        error_and_exit("Please use a numerical mtu number");
    }
    else {
        info.mtu = converted_mtu;
    }

    //check if infile exists. If not, exit with error. 
    struct stat buffer;
    int status;
    status = stat(argv[4], &buffer);
    if(status != 0){
        error_and_exit("Problem getting status of file from in_file_path");
    }else{
        info.in_file_path = argv[4];
    }

    //copy outfile into struct. TBD what to do with this one for error checking/file and directory making
    info.out_file_path = argv[5];

    return info;

}

void do_client_processing(FILE *fp, int sockfd, const sockaddr *pservaddr, socklen_t servlen){

    int n;
    char sendline[BUFFERLENGTH], recvline[BUFFERLENGTH + 1];
    while (fgets(sendline, BUFFERLENGTH, fp) != NULL) {
        cout << sendline << "\n";
        sendto(sockfd, sendline, strlen(sendline), 0, pservaddr, servlen);
        n = recvfrom(sockfd, recvline, BUFFERLENGTH, 0, NULL, NULL);
        recvline[n] = 0; //null terminate
        fputs(recvline, stdout); //temporarily put echo into stdout 
        cout << n << "\n";
    }


}


int main(int argc, char** argv)
{

    server_info info = get_commandline_args(argc, argv);
    // print_info(info);

    int sockfd;
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(info.server_port);

    //convert string IP address to binary equivalent
    if(inet_pton(AF_INET, info.server_IP.c_str(), &servaddr.sin_addr) <= 0){
        error_and_exit("Error converting string IP to binary");
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    FILE *fp;
    fp = fopen(info.in_file_path.c_str(), "r"); //pass in fp to input file to send to server
    if(fp == NULL){
        error_and_exit("Error opening file at in_file_path");
    }

    do_client_processing(fp, sockfd, (sockaddr *) &servaddr, sizeof(servaddr));

    return 0;
}
