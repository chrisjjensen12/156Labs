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
#include <iterator>
#include <locale>
#include <ctime>
#include <chrono>
#include <ctime>
#include <iomanip>
using namespace std;
#define BUFFERLENGTH 32000 //max mtu for client


struct droppc_settings{
    float droppc_decimal;
    float rand_number;
    int droppc_mode;
};

struct file_info{
    FILE * outFile;
    string file_path;
};

struct client_info{
    FILE* outfile;
    sockaddr *pcliaddr;
    int sequence_num;
    int num_bytes_in_file;
    int bytes_written_to_file;
    int packets_received;
    int packets_dropped;
    string out_file_path;
};

struct server_info{
    int port_num;
    int droppc;
    string root_folder_path;
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
    cout << "root_folder_path: " << server_info1.root_folder_path << "\n";
    return;
}

server_info get_port_and_droppc(int argc, char** argv){

    server_info info;

    int port_num = 0;
    int droppc = 0;
    //check for correct amount of command line arguments
    if(argc != 4){ 
        error_and_exit("Incorrect number of command line arguments.\nFormat: ./myserver port_number droppc root_folder_path");
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


    //get root_folder_path from command line
    info.root_folder_path = argv[3];

    //create directory path
    int check;
    check = mkdir(info.root_folder_path.c_str(),0777);
    if(check < 0){
        if(errno == EEXIST){
            // cerr << "directory already exists\n";
        }else{
            error_and_exit("Unable to create directory at root_folder_path/out_file_path");
        }
    }
    cout << "created root directory: " << info.root_folder_path << "\n";

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

file_info make_dir_and_open_file(string client_out_file_path, string root_folder_path){

    struct file_info file_info;
    FILE * outFile;
    string final_path;
    string client_given_path;

    //get directory path
    int index_of_last_slash = 0;
    for(int i = 0; i < (int)strlen(client_out_file_path.c_str()); i++){
        if(client_out_file_path.c_str()[i] == '/'){
            index_of_last_slash = i;
        }
    }

    //if given client_out_file_path is not a path, its just a file
    if(index_of_last_slash == 0){
        
        //attatch root folder to client given file, so we can open the file in the server's root folder
        final_path.append(root_folder_path);
        final_path.append("/");
        final_path.append(client_out_file_path);    

        //open file and return
        outFile = fopen(final_path.c_str(),"w");
        if (outFile==NULL)
        {
            fclose(outFile);
            error_and_exit("Error opening file at out_file_path");
        }

        file_info.file_path = final_path;
        file_info.outFile = outFile;

        return file_info;
    }

    //else, attach server's root folder to the client given path
    char directory_path[100];
    bzero(&directory_path, sizeof(directory_path));
    for(int i = 0; i < index_of_last_slash; i++){
        directory_path[i] = client_out_file_path.c_str()[i];
    }

    client_given_path = directory_path;

    //construct new path
    final_path.append(root_folder_path);
    final_path.append("/");
    final_path.append(client_given_path);


    //make new directory in server's root folder, without the file at the end
    int check;
    check = mkdir(final_path.c_str(),0777);
    if(check < 0){
        if(errno == EEXIST){
            // cerr << "directory already exists\n";
        }else{
            error_and_exit("Unable to create directory at out_file_path");
        }
    }

    cout << "created new directory in server's root folder: " << final_path << "\n";

    //construct path WITH the file at the end
    string path_with_file;
    path_with_file.append(root_folder_path);
    path_with_file.append("/");
    path_with_file.append(client_out_file_path);

    //open file in directory
    outFile = fopen(path_with_file.c_str(),"w");
    if (outFile==NULL)
    {
        fclose(outFile);
        error_and_exit("Error opening file at out_file_path");
    }

    cout << "opening file in the client given directory in the server's root folder: " << path_with_file << "\n";

    file_info.file_path = path_with_file;
    file_info.outFile = outFile;

    return file_info;

}

//########################### Server Processing ###########################

vector<client_info> parse_packet_for_info_header(string packet, vector<client_info> client_vector, sockaddr *pcliaddr, int sockfd, socklen_t len, string root_folder_path){

    int s;
    vector<client_info> client_vector_copy = client_vector;
    struct client_info new_client;
    struct file_info file_info;
    string new_file_path;
    char out_file_path[100];
    char mesg[11] = "HEADER ACK";
    int file_size = 0;
    //look for initial information packet from client
    std::size_t found = packet.find("INFORMATION_PACKET_ID");
    if (found!=std::string::npos){
        //if we found the header packet, make directory, open file, push to vector, and send ack back to client
        if(found == 0){
            // cout << "got header packet\n";
            //get out_file_path from packet
            sscanf(packet.c_str(), "%*s %*s %s %*s %d", out_file_path, &file_size);

            // cout << "file_size: " << file_size << "\n";
            //send to function to make directory
            file_info = make_dir_and_open_file(out_file_path, root_folder_path);

            //add new client address and file pointer to client_info struct
            new_client.outfile = file_info.outFile;
            new_client.pcliaddr = pcliaddr;
            new_client.sequence_num = 0;
            new_client.num_bytes_in_file = file_size;
            new_client.bytes_written_to_file = 0;
            new_client.out_file_path = file_info.file_path;
            new_client.packets_received = 0;
            new_client.packets_dropped = 0;
            

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
    struct stat sb;

    std::size_t found = packet.find("ENDER_PACKET");
    if (found!=std::string::npos){
        //if we encountered the ender packet, close file and send ack
        if(found == 0){
            // cout << "got ender packet, closing file now...\n";

            //loop through client vector
            for(vector<client_info>::const_iterator client=client_vector_copy.begin(); client!=client_vector_copy.end(); client++){

                //if this client is the one we're looking for, close file and erase entry in vector
                if(client->pcliaddr == pcliaddr){
                    // cout << "found match in vector\n";
                    found_match = 1;
                    if(fclose(client->outfile) != 0){
                        cerr << "error closing outfile\n";
                    }
                    if (stat(client->out_file_path.c_str(), &sb) == -1) {
                        error_and_exit("stat() error");
                    }
                    else { //success finding size of file
                        // cerr << "In file size: " << client->num_bytes_in_file << " bytes\n";
                        // cerr << "Out file size: " << (long long) sb.st_size << " bytes\n";

                        if(client->num_bytes_in_file == (long long) sb.st_size){
                            cerr << "File transfer complete\n";
                        }else{
                            cerr << "File incomplete\n";
                        }
                    }
                    client_vector_copy.erase(client); //erase entry in client vector
                    cerr << "Client terminated, erasing client from vector\n";
                    // cout << "Erasing client now... New size of client vector: " << client_vector_copy.size() << "\n";
                    // cout << "Percent packets dropped: " << ((float)client->packets_dropped/(float)client->packets_received)*100*1.8 << "%\n";
                    break;
                }
		        
	        }

            if(found_match == 0){
                // cout << "No match in vector\n";
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

void send_ack(vector<client_info>::iterator client, int packet_num, int sockfd, sockaddr *pcliaddr, socklen_t len){

    //time variables
    std::time_t time = std::time({});
    char timeString[std::size("yyyy-mm-ddThh:mm:ssZ")];

    //construct ack to send, if its the last packet we needed, send a 1 to let the client know it can stop
    string mesg = "ACK_SEQ_NUM: ";
    if(client->bytes_written_to_file == client->num_bytes_in_file){ //check if total number of bytes in file equals what we have now for the size of the packet
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

    // cout << "sending ACK seq num: " << packet_num << "\n";
    //send ack back to client
    s = sendto(sockfd, mesg.c_str(), mesg.length(), 0, pcliaddr, len); 
    if(s < 0){
        cerr << "sendto() failed.\n Exiting now.\n";
        exit(EXIT_FAILURE);
    } 

    //log to stdout
    std::strftime(std::data(timeString), std::size(timeString), "%FT%TZ", std::gmtime(&time));
    std::cout << timeString << ", ACK, " << packet_num << "\n";

    return;
}

vector<client_info> parse_packet_for_payload(char* char_packet, string packet, vector<client_info> client_vector, int sockfd, sockaddr *pcliaddr, socklen_t len, droppc_settings droppc_settings){

    vector<client_info> client_vector_copy = client_vector;
    int found_match = 0;

    std::size_t found = packet.find("Packet Num:");
    if (found!=std::string::npos){

        //if we found a payload packet
        if(found == 4){

            //time variables
            std::time_t time = std::time({});
            char timeString[std::size("yyyy-mm-ddThh:mm:ssZ")];

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
                // cout << "could not find a match in vector for parse payload function\n";
                return client_vector_copy;
            }

            int packet_num = 0;
            int bytes_read_from_payload = 0;
            int bytes_in_payload = 0;

            char payload[BUFFERLENGTH];

            //get sequence number and number of bytes in the packet
            sscanf(char_packet, "%*s %*s %d %*s %d", &packet_num, &bytes_in_payload);

            // cout << "recieved packet: " << packet_num << "\n";
            client->packets_received++;

            //log to stdout
            std::strftime(std::data(timeString), std::size(timeString), "%FT%TZ", std::gmtime(&time));
            std::cout << timeString << ", DATA, " << packet_num << "\n";

            //if droppc % passes, and mode == packet, drop packet
            if((droppc_settings.rand_number <= droppc_settings.droppc_decimal) && droppc_settings.droppc_mode == 1){
                //cout << "if droppc " << droppc_settings.droppc_decimal << " is less than or equal to random num " << droppc_settings.rand_number << ", drop packet\n";
                // cout << "dropping packet seq num: " << packet_num << "\n";
                std::strftime(std::data(timeString), std::size(timeString), "%FT%TZ", std::gmtime(&time));
                std::cout << timeString << ", DROP DATA, " << packet_num << "\n";
                client->packets_dropped++;
                //dont process packet, just return
                return client_vector_copy;
            }

            // cout << "packet seq num (from client): " << packet_num << " server-tracked seq num: " << client->sequence_num << "\n";

            //if sequence number sent in payload is greater than server-tracked sequence number
            if(packet_num > client->sequence_num){
                //drop packet, client needs to resend. Just return back to main loop and dont process packet
                // cout << "out of order packet detected: " << packet_num << "\n";
                std::strftime(std::data(timeString), std::size(timeString), "%FT%TZ", std::gmtime(&time));
                std::cout << timeString << ", DROP DATA, " << packet_num << "\n";
                return client_vector_copy;
            }else if(packet_num < client->sequence_num && droppc_settings.droppc_decimal != 1){ //if we already have this packet stored, send an ack for it, just in case an ack was dropped
                // cout << "we already have this packet, ack must've been dropped or its a duplicate. Resending ack now.\n";
                send_ack(client, packet_num, sockfd, pcliaddr, len);
                return client_vector_copy;
            }

            //else, write to file and increment tracked sequence number
            int start_reading_flag = 0;
            int j = 0;
            for(int i = 0; i < BUFFERLENGTH; i++){
                if(char_packet[i-1] == '\n' && char_packet[i-2] == ':'){
                    start_reading_flag = 1;
                }
                if(start_reading_flag == 1){
                    payload[j] = char_packet[i];
                    if(j == bytes_in_payload){
                        break;
                    }
                    j++;
                    bytes_read_from_payload++;
                }
            }
            
            int bytes_written_to_file = 0;
            bytes_written_to_file = fwrite(payload, sizeof(char), j, client->outfile);

            //if we actually wrote something to the file
            if(bytes_written_to_file == bytes_in_payload){
                client->bytes_written_to_file += bytes_written_to_file;
                // cout << "bytes written to file from this payload: " << bytes_written_to_file << " bytes in payload: " << bytes_in_payload << "\n";

                //if droppc % passes and mode == ack, drop ack
                if((droppc_settings.rand_number <= droppc_settings.droppc_decimal) && droppc_settings.droppc_mode == 2){
                    // cout << "dropping ACK seq num: " << packet_num << "\n";
                    std::strftime(std::data(timeString), std::size(timeString), "%FT%TZ", std::gmtime(&time));
                    std::cout << timeString << ", DROP ACK, " << packet_num << "\n";
                    client->packets_dropped++;
                    //dont send ack here, should skip it
                }else{
                    //send the ack
                    send_ack(client, packet_num, sockfd, pcliaddr, len);
                }

                //increment payload packets written to file
                client->sequence_num = client->sequence_num + 1;

            }else{ //if we didnt write the entire payload of packet to the file, then the client needs to resend it. Just drop the packet. 
                // cout << "problem occured writing packet payload to file, dropping packet\n";
                std::strftime(std::data(timeString), std::size(timeString), "%FT%TZ", std::gmtime(&time));
                std::cout << timeString << ", DROP DATA, " << packet_num << "\n";
            }

            bzero(&payload, sizeof(payload));

        }

    }

    return client_vector_copy;

}

void do_server_processing(int sockfd, sockaddr *pcliaddr, socklen_t clilen, int droppc, string root_folder_path){

    int n;
    socklen_t len;
    char mesg[BUFFERLENGTH];
    vector<client_info> client_vector;

    struct droppc_settings droppc_settings;
    droppc_settings.droppc_decimal = 0;
    droppc_settings.droppc_mode = 0;
    droppc_settings.rand_number = 0;

    //3 modes for droppc_mode: 0 is off, 1 is drop packet, 2 is drop ack
    if(droppc == 0){
        droppc_settings.droppc_mode = 0;
    }else{
        //initialize as dropping a packet
        droppc_settings.droppc_mode = 1;
    }

    droppc_settings.droppc_decimal = (float)((float)droppc / (float)100);

    // cout << "droppc_decimal: " << droppc_settings.droppc_decimal << "\n";

    for(;;){

        //generate random float from 0-1
        droppc_settings.rand_number = (float) rand()/RAND_MAX;
        //set droppc_mode for this time around
        if(droppc_settings.droppc_mode == 1){
            droppc_settings.droppc_mode = 2;
        }else if(droppc_settings.droppc_mode == 2){
            droppc_settings.droppc_mode = 1;
        }

        //get a packet
        len = clilen;
        n = recvfrom(sockfd, mesg, BUFFERLENGTH, 0, pcliaddr, &len); //reads datagram
        if(n < 0){
            cerr << "recvfrom() failed.\n Exiting now.\n";
            exit(EXIT_FAILURE);
        }
        //Look for header packet: update client info vector if new client sends header packet
        client_vector = parse_packet_for_info_header(mesg, client_vector, pcliaddr, sockfd, len, root_folder_path);

        //Look for ender packet so we know when to close the file pointer and pop that client off of the client_info vector
        client_vector = parse_packet_for_ender(mesg, client_vector, sockfd, pcliaddr, len);
        
        //Look for payload packet: if found, write payload to appropriate file and send ack to client
        client_vector = parse_packet_for_payload(mesg, mesg, client_vector, sockfd, pcliaddr, len, droppc_settings);

        // cout << mesg; 
        bzero(&mesg, sizeof(mesg));
    }

}


int main(int argc, char** argv){

    //initialize random seed using time
    srand(time(NULL));

    server_info info = get_port_and_droppc(argc, argv);
    // print_info(info);

    socket_info sockinfo = connect_to_socket(info);

    do_server_processing(sockinfo.sockfd, (sockaddr *) &sockinfo.cliaddr, sizeof(sockinfo.cliaddr), info.droppc, info.root_folder_path);

}