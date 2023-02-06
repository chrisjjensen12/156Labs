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
#include <fstream>
using namespace std;

int overhead_len = 40;
int bytes_read_from_in_file = 0;
int in_file_size = 0;

struct server_info {
    string server_IP;
    int server_port;
    int mtu;
    int winsz;
    string in_file_path;
    string out_file_path;
};

struct socket_info {
    int sockfd;
    struct sockaddr_in servaddr;
};

//########################### Helper Functions/Information Gathering ###########################

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

server_info get_commandline_args(int argc, char** argv){

    server_info info;

    if(argc != 7){
        cerr << "Incorrect number of command line arguments.\nFormat: ./myclient server_ip server_port mtu winsz in_file_path out_file_path\n";
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
        info.server_port = converted_port;
    }

    if(info.server_port <= 1024){
        error_and_exit("Port number should be greater than 1024, and less than 65536");
    }else if(info.server_port >= 65536){
        error_and_exit("Port number should be greater than 1024, and less than 65536");
    }

    //check if mtu is integer
    info.mtu = 0;
    if (isdigit(argv[3][0]))
    {
        info.mtu = stoi(argv[3]);
    }else{
        error_and_exit("Please enter a numerical mtu value");
    }

    //check if winsz is integer
    info.winsz = 0;
    if (isdigit(argv[4][0]))
    {
        info.winsz = stoi(argv[4]);
    }else{
        error_and_exit("Please enter a numerical winsz value");
    }

    //check if infile exists. If not, exit with error. 
    struct stat buffer;
    int status;
    status = stat(argv[5], &buffer);
    if(status != 0){
        error_and_exit("Problem getting status of file from in_file_path");
    }else{
        info.in_file_path = argv[5];
    }

    //copy outfile into struct. Send to server so that it can create the path
    info.out_file_path = argv[6];

    return info;

}

void print_info(server_info server_info1){
    cout << "Server IP: " << server_info1.server_IP << "\n";
    cout << "Server Port: " << server_info1.server_port << "\n";
    cout << "MTU: " << server_info1.mtu << "\n";
    cout << "Winsz: " << server_info1.winsz << "\n";
    cout << "in file path: " << server_info1.in_file_path << "\n";
    cout << "out file path: " << server_info1.out_file_path << "\n";
    return;
}

socket_info connect_to_socket(server_info info){
    struct socket_info sockinfo;
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
    if(sockfd < 0){
        error_and_exit("Error creating socket");
    }

    sockinfo.sockfd = sockfd;
    sockinfo.servaddr = servaddr;

    return sockinfo;
}

int check_and_open_in_file(server_info info){
    struct stat sb;

    if (stat(info.in_file_path.c_str(), &sb) == -1) {
        error_and_exit("stat() error");
    }
    else { //success finding size of file
        // cout << "In file size: " << (long long) sb.st_size << " bytes\n";
        in_file_size = (long long) sb.st_size;
    }

    int in_fd;
    in_fd = open(info.in_file_path.c_str(), O_RDONLY);
    if(in_fd < 0){
        error_and_exit("Error opening file at in_file_path");
    }
    return in_fd;
}

//########################### Client Processing ###########################

void send_client_info_to_server(int sockfd, const sockaddr *pservaddr, socklen_t servlen, string out_file_path){

    int n = 0;
    int s = 0;
    struct timeval tv;
    tv.tv_sec = 60; //60s timeout
    tv.tv_usec = 0;
    char ackbuffer[5000];
    string packet = "INFORMATION_PACKET_ID\r\n\r\nout_file_path: ";
    packet.append(out_file_path);
    // cout << packet << "\n";
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); //set timeout 
    s = sendto(sockfd, packet.c_str(), 5000, 0, pservaddr, servlen);
    if(s < 0){
        error_and_exit("sendto() failed.");
    }
    n = recvfrom(sockfd, ackbuffer, 5000, 0, NULL, NULL);

    cout << ackbuffer;

    if(n < 0){
        if(errno == EINTR){
            //interrupted call
            error_and_exit("Something interrupted the call to sendto()");
        }else if(errno == EAGAIN){
            //server timed out
            error_and_exit("Cannot detect server");
        }else if(errno == EWOULDBLOCK){
            //server timed out
            error_and_exit("Cannot detect server");
        }else{
            //other recvfrom error
            error_and_exit("recvfrom() failed.");
        }
    }

}

void do_client_processing(int in_fd, int sockfd, const sockaddr *pservaddr, socklen_t servlen, int mtu, int winsz, string out_file_path){

    if(overhead_len >= mtu){ //check mtu can at least send one byte with overhead
        error_and_exit("Required minimum MTU is 41");
    }else if(mtu >= 32000){ //check that the mtu is less than 32000
        error_and_exit("MTU must be less than 32000");
    }

    //send information about the file thats about to be sent, including the out file path that the server needs to make
    send_client_info_to_server(sockfd, pservaddr, servlen, out_file_path);

    int n;
    char data[mtu-overhead_len+1];
    int packet_num = 0;
    char echoed_packet[mtu];
    char first_part[overhead_len+1];
    int bytes_in_packet = 0;

    bzero(&first_part, sizeof(first_part));
    bzero(&echoed_packet, sizeof(echoed_packet));
    bzero(&data, sizeof(data));

    string packet;

    //read file and split into mtu sized packets
    while ((n = read(in_fd, data, mtu-overhead_len)) >= 0) { //splits file into mtu-overhead sized chunks
        bytes_read_from_in_file += n;
        if(n < 0){
            error_and_exit("Read() error");
        }

        if(n == 0){ //eof
            break;
        }

        //prepare packet by adding overhead and data payload
        bytes_in_packet = sprintf(first_part, "\r\n\r\nPacket Num: %d\r\n\r\nPayload:\n", packet_num);
        bytes_in_packet += n; //add bytes from data portion
        packet = first_part;
        packet.append(data, n);

        // cout << packet;

        //send packet to server
        // send_packet_to_server(sockfd, pservaddr, servlen, packet, mtu, echoed_packet, bytes_in_packet);
        
        bytes_in_packet = 0;
        packet.clear();  
        bzero(&first_part, sizeof(first_part));
        bzero(&echoed_packet, sizeof(echoed_packet));
        bzero(&data, sizeof(data)); //zero out data for next read
        packet_num++;
    }


}

int main(int argc, char** argv){
    server_info info = get_commandline_args(argc, argv);
    // print_info(info);
    socket_info socketinfo = connect_to_socket(info); //returns information about server socket
    int in_fd = check_and_open_in_file(info); //returns fd for given in file
    do_client_processing(in_fd, socketinfo.sockfd, (sockaddr *) &socketinfo.servaddr, sizeof(socketinfo.servaddr), info.mtu, info.winsz, info.out_file_path);

    //A few debugging printouts before exiting:
    cout << "\n\nBytes read from in file: " << bytes_read_from_in_file << "\n";
    cout << "In file size: " << in_file_size << "\n";

    close(in_fd); //close in file once we're done with everything
    return 0;
}