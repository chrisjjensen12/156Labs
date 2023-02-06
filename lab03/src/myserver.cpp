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
#define BUFFERLENGTH 32000 //max mtu for client

struct server_info{
    int port_num;
    int droppc;
};

struct socket_info{
    int sockfd;
    struct sockaddr_in cliaddr;
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

void print_info(server_info server_info1){
    cout << "Port Number: " << server_info1.port_num << "\n";
    cout << "droppc: " << server_info1.droppc << "\n";
    return;
}

server_info get_port_and_droppc(int argc, char** argv){

    server_info info;

    int port_num = 0;
    int droppc = 0;
    //check for correct amount of command line arguments
    if(argc != 3){ 
        error_and_exit("Incorrect number of command line arguments.\nFormat: ./myserver port_number droppc");
    }

    //check if port_num is integer
    if (isdigit(argv[1][0]))
    {
        port_num = stoi(argv[1]);
    }else{
        error_and_exit("Please use a correct port number. Exiting now.");
    }

    if(port_num <= 1024){
        error_and_exit("Port number should be greater than 1024, and less than 65536");
    }else if(port_num >= 65536){
        error_and_exit("Port number should be greater than 1024, and less than 65536");
    }

    //check if droppc is integer
    if (isdigit(argv[2][0]))
    {
        droppc = stoi(argv[2]);
    }else{
        error_and_exit("Please enter a numerical droppc value");
    }

    if(droppc > 100 || droppc < 0){
        error_and_exit("Please choose a value for droppc between 0 and 100");
    }


    info.port_num = port_num;
    info.droppc = droppc;

    return info;
}

socket_info connect_to_socket(server_info info){

    socket_info socketinfo;

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
    servaddr.sin_port = htons(info.port_num); //converts from MY local byte order to network standard


    if(bind(sockfd, (sockaddr *) &servaddr, sizeof(servaddr)) < 0){
        cerr << "bind() failed. Exiting now.\n";
        exit(EXIT_FAILURE);
    }

    socketinfo.sockfd = sockfd;
    socketinfo.cliaddr = cliaddr;

    return socketinfo;

}

void make_outfile_dir(string out_file_path){

    //get directory path
    int index_of_last_slash = 0;
    for(int i = 0; i < (int)strlen(out_file_path.c_str()); i++){
        if(out_file_path.c_str()[i] == '/'){
            index_of_last_slash = i;
        }
    }

    if(index_of_last_slash == 0){ //file is not a path and is in executable directory
        //just return so we can open file at where the executable exists
        return;
    }

    char directory_path[100];
    bzero(&directory_path, sizeof(directory_path));
    for(int i = 0; i < index_of_last_slash; i++){
        directory_path[i] = out_file_path.c_str()[i];
    }

    cout << directory_path << "\n";

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

    return;

}

FILE* open_file(string out_file_path){
    FILE * outFile;
    outFile = fopen(out_file_path.c_str(),"w");
    if (outFile==NULL)
    {
        fclose(outFile);
        error_and_exit("Error opening file at out_file_path");
    }

    return outFile;
}

//########################### Server Processing ###########################

void parse_packet_for_info_header(string packet){
    char out_file_path[100];
    //look for initial information packet from client
    std::size_t found = packet.find("INFORMATION_PACKET_ID");
    if (found!=std::string::npos){
        if(found == 0){
            //get out_file_path from packet
            sscanf(packet.c_str(), "%*s %*s %s", out_file_path);
            //send to function to make directory
            make_outfile_dir(out_file_path);

            //open file at directory
            FILE * outFile = open_file(out_file_path);

            fwrite("bruh", sizeof(char), 4, outFile);
            fclose(outFile);
        }
    }

    return;
}


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
        parse_packet_for_info_header(mesg);

        //send ack
        s = sendto(sockfd, mesg, n, 0, pcliaddr, len); //sends it back to sender
        if(s < 0){
            cerr << "sendto() failed.\n Exiting now.\n";
            exit(EXIT_FAILURE);
        }
        // cout << mesg;
    }

}


int main(int argc, char** argv){

    server_info info = get_port_and_droppc(argc, argv);
    // print_info(info);

    socket_info sockinfo = connect_to_socket(info);

    do_server_processing(sockinfo.sockfd, (sockaddr *) &sockinfo.cliaddr, sizeof(sockinfo.cliaddr));

}