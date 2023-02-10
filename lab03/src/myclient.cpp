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
#include <vector>
#include <algorithm>
#include<list>
#include<signal.h>
using namespace std;


//go back n pointers
int basesn = 0;
int nextsn = 0;
int timeout = 0;
int basesn_packet_resent_number = 0;
int basesn_seq_num = 0;

int last_ack = 0;
int overhead_len = 60;
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

struct packet_info{
    string packet;
    int seq_num;
    int bytes_in_packet;
};

struct socket_info {
    int sockfd;
    struct sockaddr_in servaddr;
};

//########################### Helper Functions/Information Gathering ###########################

void sig_handler(int signum){
 
  printf("Triggered timeout!\n");

  timeout = 1;

  return;
}

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

void send_client_info_to_server(int sockfd, const sockaddr *pservaddr, socklen_t servlen, string out_file_path, int ender_or_header){

    int n = 0;
    int s = 0;
    struct timeval tv;
    tv.tv_sec = 60; //60s timeout
    tv.tv_usec = 0;
    char ackbuffer[5000];
    bzero(&ackbuffer, sizeof(ackbuffer));
    string packet;
    if(ender_or_header == 1){
        cout << "sending header packet...\n";
        packet = "INFORMATION_PACKET_ID\r\n\r\nout_file_path: ";
        packet.append(out_file_path);
        packet.append("\r\n\r\nbytes_in_file: ");
        string in_file_size_str = to_string(in_file_size);
        packet.append(in_file_size_str);
    }else{
        cout << "sending ender packet...\n";
        packet = "ENDER_PACKET\r\n\r\nout_file_path: ";
        packet.append(out_file_path);
    }
    // cout << packet << "\n";
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); //set timeout 
    s = sendto(sockfd, packet.c_str(), 5000, 0, pservaddr, servlen);
    if(s < 0){
        error_and_exit("sendto() failed.");
    }
    n = recvfrom(sockfd, ackbuffer, 5000, 0, NULL, NULL);

    cout << ackbuffer << "\n";

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

    return;

}


void do_client_processing(int in_fd, int sockfd, const sockaddr *pservaddr, socklen_t servlen, int mtu, int winsz, string out_file_path){

    if(overhead_len >= mtu){ //check mtu can at least send one byte with overhead
        error_and_exit("Required minimum MTU is 61");
    }else if(mtu >= 32000){ //check that the mtu is less than 32000
        error_and_exit("MTU must be less than 32000");
    }

    //send information about the file thats about to be sent, including the out file path that the server needs to make
    send_client_info_to_server(sockfd, pservaddr, servlen, out_file_path, 1);
    //TODO: wait for ack and retransmit if needed

    int s;
    int n;
    int ack_n;
    int ack_seq_num = 0;
    char data[mtu-overhead_len+1];
    int packet_num = 0;
    char first_part[overhead_len+1];
    int bytes_in_packet = 0;
    int initial_timer = 0;

    bzero(&first_part, sizeof(first_part));
    bzero(&data, sizeof(data));

    string packet;
    char ack_buffer[2048];

    list<packet_info> window;

    //while the last ack has not been received from server, keep sending packets and looking for acks
    while (last_ack != 1) {
        
        if(nextsn < basesn+winsz && !timeout){
            //construct new packet and send off
            n = read(in_fd, data, mtu-overhead_len); //splits file into mtu-overhead sized chunks
            bytes_read_from_in_file += n;
            if(n < 0){
                error_and_exit("Read() error");
            }
            if(n == 0){ //eof
                //send ender packet
                // send_client_info_to_server(sockfd, pservaddr, servlen, out_file_path, 0);
                //TODO: wait for ack and retransmit if needed
                // break;
            }

            if(n != 0){

                struct packet_info new_packet;
                //prepare packet by adding overhead and data payload
                bytes_in_packet = sprintf(first_part, "\r\n\r\nPacket Num: %d\r\n\r\nLen: %d\r\n\r\nPayload:\n", packet_num, n);
                bytes_in_packet += n; //add bytes from data portion
                packet = first_part;
                packet.append(data, n);

                // cout << packet;

                // send packet to server
                cout << "sending packet: " << packet_num << " num bytes in payload: " << n << "\n";

                s = sendto(sockfd, packet.c_str(), bytes_in_packet, 0, pservaddr, servlen);
                if(s < 0){
                    error_and_exit("sendto() failed.");
                }
                //increment nextsn
                nextsn++;

                new_packet.bytes_in_packet = bytes_in_packet;
                new_packet.packet = packet;
                new_packet.seq_num = packet_num;

                //if vector is full, pop off the front and add new packet
                if((int)window.size() == winsz){
                    window.pop_front();
                    window.push_back(new_packet);
                }else{
                    window.push_back(new_packet);
                }

                //set in case of timeout
                basesn_seq_num = window.front().seq_num;

                if(initial_timer == 0){
                    // cout << "start inital timer\n";
                    alarm(3);
                    initial_timer = 1;
                }

                packet_num++;
            }

        }

        //handle a timeout
        if(timeout){
            //check for if packet at basesn has been here before
            if(basesn_seq_num == window.front().seq_num){
                basesn_packet_resent_number++;
            }else{
                basesn_packet_resent_number = 0;
            }
            if(basesn_packet_resent_number == 4){
                error_and_exit("Resent same packet too many times, exiting now");
            }
            cout << "packet at basesn should be: " << window.front().seq_num << "\n";
            //re-send packets in window 
            cout << "resending packets currently in window\n";
            for (auto const &i: window) {
                cout << "resending packet: " << i.seq_num << ", bytes in packet: " << i.bytes_in_packet << "\n";
                s = sendto(sockfd, i.packet.c_str(), bytes_in_packet, 0, pservaddr, servlen);
                if(s < 0){
                    error_and_exit("sendto() failed.");
                }
            }

            //reset timer
            alarm(3);
            timeout = 0;
        }

        //call a nonblocking recvfrom to get any available acks from server
        ack_n = recvfrom(sockfd, ack_buffer, 2048, MSG_DONTWAIT, NULL, NULL);

        //got a packet
        if(ack_n != -1){
            sscanf(ack_buffer, "%*s %d %*s %d", &ack_seq_num, &last_ack);
            cout << "Got ack for seq num: " << ack_seq_num << " last ack: " << last_ack << "\n";
            if(last_ack == 1){
                //sends ender packet
                send_client_info_to_server(sockfd, pservaddr, servlen, out_file_path, 0);
            }

            basesn = ack_seq_num + 1;

            if(basesn == nextsn){
                //stopping timer
                cout << "stopping timer\n";
                alarm(0);
            }else{
                // cout << "start timer\n";
                alarm(3);
            }
        }
        
        bytes_in_packet = 0;
        packet.clear(); 
        bzero(&ack_buffer, sizeof(ack_buffer));
        bzero(&first_part, sizeof(first_part));
        bzero(&data, sizeof(data)); //zero out data for next read
    }


}

int main(int argc, char** argv){
    signal(SIGALRM,sig_handler); // Register signal handler
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