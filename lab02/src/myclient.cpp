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
int overhead_len = 60;
int packet_counter = 0; 
int bytes_read_from_echo = 0;
int bytes_read_from_in_file = 0;
int bytes_put_in_payload = 0;
int bytes_sent_to_server = 0;

struct server_info {
    string server_IP;
    int server_port;
    int mtu;
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
    ofstream file;
    
    //get directory path
    int index_of_last_slash = 0;
    for(int i = 0; i < (int)strlen(info.out_file_path.c_str()); i++){
        if(info.out_file_path.c_str()[i] == '/'){
            index_of_last_slash = i;
        }
    }

    if(index_of_last_slash == 0){ //file is not a path and is in executable directory
        //create file
        return info;
    }

    char directory_path[100];
    for(int i = 0; i < index_of_last_slash; i++){
        directory_path[i] = info.out_file_path.c_str()[i];
    }

    //create directory path
    int check;
    check = mkdir(directory_path,0777);
    if(check < 0){
        if(errno == EEXIST){
            // cerr << "directory already exists\n";
        }else{
            error_and_exit("Unable to create directory at out_file_path");
        }
    }

    return info;

}

void send_packet_to_server(int sockfd, const sockaddr *pservaddr, socklen_t servlen, string packet, int mtu, char* echoed_packet, int bytes_in_packet){

    int n = 0;
    int s = 0;
    struct timeval tv;
    tv.tv_sec = 60; //60s timeout
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); //set timeout 
    s = sendto(sockfd, packet.c_str(), bytes_in_packet, 0, pservaddr, servlen);
    if(s < 0){
        error_and_exit("sendto() failed.");
    }
    n = recvfrom(sockfd, echoed_packet, mtu, 0, NULL, NULL);

    if(n < 0){
        if(errno == EINTR){
            //interrupted call, try sending packet again
            recvfrom(sockfd, echoed_packet, mtu, 0, NULL, NULL);
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

    // if(s != n){
    //     cerr << "Error! Bytes sent to server: " << s << " Bytes received from server: " << n << "\n";
    //     error_and_exit("Sent packet # of bytes does not equal recieved packet # of bytes");

    // }

}

void parse_echoed_packet(char* echoed_packet, int mtu, FILE * outFile, int bytes_in_packet){

    char payload[mtu];
    int packet_num = 0;

    bzero(&payload, sizeof(payload));

    sscanf(echoed_packet, "%*s %*s %d %*s %*s", &packet_num);

    // cout << "packet counter: " << packet_counter << " Packet num: " << packet_num << "\n";


    if(packet_counter != packet_num){
        error_and_exit("Packet loss detected");
    }

    int start_reading_flag = 0;
    int j = 0;
    for(int i = 0; i < bytes_in_packet; i++){
        if(echoed_packet[i-1] == '\n' && echoed_packet[i-2] == ':'){
            start_reading_flag = 1;
        }
        if(start_reading_flag == 1){
            payload[j] = echoed_packet[i];
            // fputc(echoed_packet[i], outFile);
            j++;
            bytes_read_from_echo++;
        }
    }
    
    fwrite(payload, sizeof(char), j, outFile);
    // cout << packet_num << "\n";
    // write(out_fd, payload, j);
    // cout << payload;

    bzero(&echoed_packet, sizeof(echoed_packet));
    bzero(&payload, sizeof(payload));

    packet_counter++;

}


void do_client_processing(int in_fd, FILE * outFile, int sockfd, const sockaddr *pservaddr, socklen_t servlen, int mtu){

    if(overhead_len >= mtu){ //check mtu can at least send one byte with overhead
        error_and_exit("Required minimum MTU is 61");
    }else if(mtu >= 32000){ //check that the mtu is less than 32000
        error_and_exit("MTU must be less than 32000");
    }


    int n;
    char data[mtu-overhead_len+1];
    char packet[mtu];
    int packet_num = 0;
    char echoed_packet[mtu];
    char first_part[overhead_len+1];
    int bytes_in_packet = 0;

    bzero(&first_part, sizeof(first_part));
    bzero(&echoed_packet, sizeof(echoed_packet));
    bzero(&data, sizeof(data));
    bzero(&packet, sizeof(packet));

    string packet1;

    while ((n = read(in_fd, data, mtu-overhead_len)) >= 0) { //splits file into mtu-overhead sized chunks
        bytes_read_from_in_file += n;
        if(n < 0){
            error_and_exit("Read() error");
        }

        if(n == 0){ //eof
            break;
        }

        //prepare packet by adding overhead and data payload
        bytes_in_packet = sprintf(first_part, "\r\n\r\nPacket Num: %d\r\n\r\nLen: %d\r\n\r\nPayload:\n", packet_num, n);
        bytes_in_packet += n; //add bytes from data portion
        packet1 = first_part;
        packet1.append(data, n);

        // cout << packet1;

        //send packet to server
        send_packet_to_server(sockfd, pservaddr, servlen, packet1, mtu, echoed_packet, bytes_in_packet);

        parse_echoed_packet(echoed_packet, mtu, outFile, bytes_in_packet);
        
        bytes_in_packet = 0;
        // cout << packet;
        packet1.clear();  
        bzero(&first_part, sizeof(first_part));
        bzero(&echoed_packet, sizeof(echoed_packet));
        bzero(&data, sizeof(data)); //zero out data for next read
        bzero(&packet, sizeof(packet)); //zero out packet for next read
        packet_num++;
    }

    close(in_fd);

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

    struct stat sb;

    if (stat(info.in_file_path.c_str(), &sb) == -1) {
        error_and_exit("stat() error");
    }
    else {
            // cout << "In file size: " << (long long) sb.st_size << " bytes\n";
    }

    int in_fd;
    in_fd = open(info.in_file_path.c_str(), O_RDONLY);
    if(in_fd < 0){
        error_and_exit("Error opening file at in_file_path");
    }

    FILE * outFile;
    outFile = fopen(info.out_file_path.c_str(),"w");
    if (outFile==NULL)
    {
        fclose(outFile);
        error_and_exit("Error opening file at out_file_path");
    }


    do_client_processing(in_fd, outFile, sockfd, (sockaddr *) &servaddr, sizeof(servaddr), info.mtu);

    fclose(outFile);
    close(in_fd);

    // struct stat so;

    // if (stat(info.out_file_path.c_str(), &so) == -1) {
    //     error_and_exit("stat() error");
    // }
    // else {
    //         cout << "Out file size: " << (long long) so.st_size << " bytes\n";
    // }

    // cout << "Bytes read from echo payloads: " << bytes_read_from_echo << "\n";
    // cout << "Bytes read from in file: " << bytes_read_from_in_file << "\n";
     
    return 0;
}
