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
#include <sys/stat.h>

using namespace std;
#define BUFFERLENGTH 4096
int overhead_len = 40; 

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


void do_client_processing(int fd, int sockfd, const sockaddr *pservaddr, socklen_t servlen, int mtu){


    if(overhead_len >= mtu){ //check mtu
        error_and_exit("Required minimum MTU is 41");
    }

    int n;
    char data[mtu-overhead_len+1];
    char packet[mtu];
    int packet_num = 0;
    int counter = 0;
    char packets[5][mtu];
    char recvline[BUFFERLENGTH + 1];

    bzero(&data, sizeof(data));
    bzero(&packet, sizeof(packet));

    while ((n = read(fd, data, mtu-overhead_len)) >= 0) { //splits file into mtu-overhead sized chunks

        if(n < 0){
            error_and_exit("Read() error");
        }

        //prepare packet by adding overhead and data payload
        sprintf(packet, "\r\n\r\nPacket Num: %d\r\n\r\nPayload:\n%s", packet_num, data);

        strcpy(packets[counter], packet);

        if(counter == 4 || n == 0){
            // cout << "\n##################\n";

            if(n != 0){
                for(int i = 0; i < 5; i++){ //send burst of 5 packets and wait
                    sendto(sockfd, packets[i], strlen(packets[i]), 0, pservaddr, servlen);
                }
                n = recvfrom(sockfd, recvline, BUFFERLENGTH, 0, NULL, NULL); //get response from server
                cout << recvline;
            }else{
                for(int i = 0; i < counter; i++){ //send burst of whatever is left
                    sendto(sockfd, packets[i], strlen(packets[i]), 0, pservaddr, servlen);
                }
                n = recvfrom(sockfd, recvline, BUFFERLENGTH, 0, NULL, NULL); //get response from server
                cout << recvline;
                break;
            }

            counter = 0;
            bzero(&packets[0], sizeof(packets[0]));
            bzero(&packets[1], sizeof(packets[1]));
            bzero(&packets[2], sizeof(packets[2]));
            bzero(&packets[3], sizeof(packets[3]));
            bzero(&packets[4], sizeof(packets[4]));
        }
        
        // cout << packet;
        bzero(&data, sizeof(data)); //zero out data for next read
        bzero(&packet, sizeof(packet)); //zero out packet for next read
        packet_num++;
        counter++;
    }

    close(fd);


    // int n;
    // struct timeval tv;
    // tv.tv_sec = 3;
    // tv.tv_usec = 0;
    // setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // char sendline[BUFFERLENGTH], recvline[BUFFERLENGTH + 1];
    // while (fgets(sendline, BUFFERLENGTH, fp) != NULL) {
    //     sendto(sockfd, sendline, strlen(sendline), 0, pservaddr, servlen);
    //     n = recvfrom(sockfd, recvline, BUFFERLENGTH, 0, NULL, NULL);
    //     if(n < 0){
    //         if(errno == EINTR){
    //             break;
    //         }
    //     }

    //     recvline[n] = 0; //null terminate
    //     fputs(recvline, stdout); //temporarily put echo into stdout 
    // }


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

    int fd;
    fd = open(info.in_file_path.c_str(), O_RDONLY);
    if(fd < 0){
        error_and_exit("Error opening file at in_file_path");
    }

    do_client_processing(fd, sockfd, (sockaddr *) &servaddr, sizeof(servaddr), info.mtu);

    return 0;
}
