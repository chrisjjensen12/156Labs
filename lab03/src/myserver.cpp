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
using namespace std;
#define BUFFERLENGTH 32000 //max mtu for client

struct client_info{
    FILE* outfile;
    sockaddr *pcliaddr;
    int sequence_num;
    int num_bytes_in_file;
    int bytes_written_to_file;
};

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

    // cout << directory_path << "\n";

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

vector<client_info> parse_packet_for_info_header(string packet, vector<client_info> client_vector, sockaddr *pcliaddr, int sockfd, socklen_t len){

    int s;
    vector<client_info> client_vector_copy = client_vector;
    struct client_info new_client;
    char out_file_path[100];
    char mesg[11] = "HEADER ACK";
    int file_size = 0;
    //look for initial information packet from client
    std::size_t found = packet.find("INFORMATION_PACKET_ID");
    if (found!=std::string::npos){
        //if we found the header packet, make directory, open file, push to vector, and send ack back to client
        if(found == 0){
            cout << "got header packet\n";
            //get out_file_path from packet
            sscanf(packet.c_str(), "%*s %*s %s %*s %d", out_file_path, &file_size);

            cout << "file_size: " << file_size << "\n";
            //send to function to make directory
            make_outfile_dir(out_file_path);

            //open file at directory
            FILE * outFile = open_file(out_file_path);

            //add new client address and file pointer to client_info struct
            new_client.outfile = outFile;
            new_client.pcliaddr = pcliaddr;
            new_client.sequence_num = 0;
            new_client.num_bytes_in_file = file_size;
            new_client.bytes_written_to_file = 0;

            //push client info struct to vector and return
            client_vector_copy.push_back(new_client);

            //send ack that we got header file
            s = sendto(sockfd, mesg, 11, 0, pcliaddr, len); 
            if(s < 0){
                cerr << "sendto() failed.\n Exiting now.\n";
                exit(EXIT_FAILURE);
            }
            return client_vector_copy;

        }
    }

    return client_vector_copy;
}


vector<client_info> parse_packet_for_ender(string packet, vector<client_info> client_vector, int sockfd, sockaddr *pcliaddr, socklen_t len){

    vector<client_info> client_vector_copy = client_vector;

    int s;
    char mesg[10] = "ENDER ACK";
    int found_match = 0;
    std::vector<client_info>::iterator client;

    std::size_t found = packet.find("ENDER_PACKET");
    if (found!=std::string::npos){
        //if we encountered the ender packet, close file and send ack
        if(found == 0){
            cout << "got ender packet, closing file now...\n";

            //loop through client vector
            for(vector<client_info>::const_iterator client=client_vector_copy.begin(); client!=client_vector_copy.end(); client++){

                //if this client is the one we're looking for, close file and erase entry in vector
                if(client->pcliaddr == pcliaddr){
                    cout << "found match in vector\n";
                    found_match = 1;
                    if(fclose(client->outfile) != 0){
                        cout << "error closing outfile\n";
                    }
                    client_vector_copy.erase(client); //erase entry in client vector
                    break;
                }
		        
	        }

            if(found_match == 0){
                cout << "No match in vector\n";
                return client_vector_copy;
            }

            //send ack that we got ender packet
            s = sendto(sockfd, mesg, 10, 0, pcliaddr, len); 
            if(s < 0){
                cerr << "sendto() failed.\n Exiting now.\n";
                exit(EXIT_FAILURE);
            }


        }else{ //else return to function
            return client_vector_copy;
        }
    }

    return client_vector_copy;
}

vector<client_info> parse_packet_for_payload(string packet, vector<client_info> client_vector, int sockfd, sockaddr *pcliaddr, socklen_t len){

    vector<client_info> client_vector_copy = client_vector;
    int found_match = 0;

    std::size_t found = packet.find("Packet Num:");
    if (found!=std::string::npos){

        //if we found a payload packet
        if(found == 4){

            vector<client_info>::iterator client;

            //find client in vector of clients
            for(client=client_vector_copy.begin(); client!=client_vector_copy.end(); client++){
                //if we found client in vector of clients
                if(client->pcliaddr == pcliaddr){
                    found_match = 1;
                    break;
                }
	        }

            if(found_match == 0){
                cout << "could not find a match in vector for parse payload function\n";
                return client_vector_copy;
            }

            int packet_num = 0;
            int bytes_read_from_payload = 0;

            char payload[BUFFERLENGTH];

            sscanf(packet.c_str(), "%*s %*s %d %*s %*s", &packet_num);

            cout << "packet seq num: " << packet_num << "\n";

            //if sequence number sent in payload does not match server-tracked sequence number
            if(client->sequence_num != packet_num){
                //drop packet, client needs to resend. Just return back to main loop and dont process packet
                cout << "out of order packet detected: " << packet_num << "\n";
                return client_vector_copy;
            }

            //else, write to file and increment tracked sequence number
            int start_reading_flag = 0;
            int j = 0;
            for(int i = 0; i < (int)packet.length(); i++){
                if(packet.c_str()[i-1] == '\n' && packet.c_str()[i-2] == ':'){
                    start_reading_flag = 1;
                }
                if(start_reading_flag == 1){
                    payload[j] = packet.c_str()[i];
                    // fputc(echoed_packet[i], outFile);
                    j++;
                    bytes_read_from_payload++;
                }
            }

            client->bytes_written_to_file = client->bytes_written_to_file+j;
            
            fwrite(payload, sizeof(char), j, client->outfile);
            bzero(&payload, sizeof(payload));

            //construct ack to send, if its the last packet we needed, send a 1 to let the client know it can stop
            string mesg = "ACK_SEQ_NUM: ";
            if(client->bytes_written_to_file == client->num_bytes_in_file){
                string seq_num = to_string(packet_num);
                mesg.append(seq_num);
                mesg.append("\r\n\r\nLAST_ACK: ");
                mesg.append("1");
            }else{
                string seq_num = to_string(packet_num);
                mesg.append(seq_num);
                mesg.append("\r\n\r\nLAST_ACK: ");
                mesg.append("0");
                //TODO: now we can close file
            }

            int s;
            //send ack back to client
            s = sendto(sockfd, mesg.c_str(), mesg.length(), 0, pcliaddr, len); 
            if(s < 0){
                cerr << "sendto() failed.\n Exiting now.\n";
                exit(EXIT_FAILURE);
            }

            //increment payload packets written to file
            client->sequence_num = client->sequence_num + 1; 

        }

    }

    return client_vector_copy;

}

void do_server_processing(int sockfd, sockaddr *pcliaddr, socklen_t clilen){

    int n;
    socklen_t len;
    char mesg[BUFFERLENGTH];

    string packet;
    vector<client_info> client_vector;

   for(;;){
        len = clilen;
        n = recvfrom(sockfd, mesg, BUFFERLENGTH, 0, pcliaddr, &len); //reads datagram
        if(n < 0){
            cerr << "recvfrom() failed.\n Exiting now.\n";
            exit(EXIT_FAILURE);
        }
        //Look for header packet: update client info vector if new client sends header packet
        client_vector = parse_packet_for_info_header(mesg, client_vector, pcliaddr, sockfd, len);

        //Look for ender packet so we know when to close the file pointer and pop that client off of the client_info vector
        client_vector = parse_packet_for_ender(mesg, client_vector, sockfd, pcliaddr, len);

        //Look for payload packet: if found, write payload to appropriate file and send ack to client
        client_vector = parse_packet_for_payload(mesg, client_vector, sockfd, pcliaddr, len);

        // cout << mesg;
        bzero(&mesg, sizeof(mesg));
    }

}


int main(int argc, char** argv){

    server_info info = get_port_and_droppc(argc, argv);
    // print_info(info);

    socket_info sockinfo = connect_to_socket(info);

    do_server_processing(sockinfo.sockfd, (sockaddr *) &sockinfo.cliaddr, sizeof(sockinfo.cliaddr));

}