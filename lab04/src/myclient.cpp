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
#include <list>
#include <signal.h>
#include <sys/time.h>
#include <iterator>
#include <locale>
#include <ctime>
#include <pthread.h>
#include <cstdlib>
#include <chrono>
#include <iomanip>
using namespace std;

//consistent threads wont change these globals
int servn = 0;
int overhead_len = 60;
int in_file_size = 0;
string in_file_path_global;

//mutex lock 
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct thread_globals{
    //go back n pointers
    int basesn = 0;
    int nextsn = 0;
    int basesn_packet_resent_number = 0;
    int old_seq_num = 0;
    int new_seq_num = 0;
    //other flags
    int last_ack = 0;
    int bytes_read_from_in_file = 0;
};

struct socket_info {
    int sockfd;
    int local_port;
    struct sockaddr_in servaddr;
};

struct server_info {
    string server_IP;
    int server_port;
    int mtu;
    int winsz;
    string in_file_path;
    string out_file_path;
};

struct thread_arguments{
    server_info info;
    thread_globals globals;
    socket_info sockinfo;
};

struct packet_info{
    string packet;
    int seq_num;
    int bytes_in_packet;
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

server_info* parse_config(string conf_file, int servn, int mtu, int winsz, string in_file_path, string out_file_path){

    server_info* server_arr = new server_info[servn];
    int counter = 0;

    std::ifstream cFile (conf_file);
    if (cFile.is_open())
    {
        std::string line;
        while(getline(cFile, line)){

            //exit when we have servn servers stored in server_arr
            if(counter == servn){
                break;
            }

            //ignore commments and empty lines
            if( line.empty() || line[0] == '#' ){
                continue;
            }
            auto delimiterPos = line.find(" ");
            string ip_addr = line.substr(0, delimiterPos);
            string port = line.substr(delimiterPos + 1);

            //assign string to server_ip. Will throw error later if this is incorrect
            server_arr[counter].server_IP = ip_addr;

            //check if port is integer
            char* p;
            long converted_port = strtol(port.c_str(), &p, 10);
            if (*p) {
                error_and_exit("Please use a numerical port number in config file");
            }
            else {
                server_arr[counter].server_port = converted_port;
            }

            //check if port is within range
            if(server_arr[counter].server_port <= 1024){
                error_and_exit("Port number in config file should be greater than 1024, and less than 65536");
            }else if(server_arr[counter].server_port >= 65536){
                error_and_exit("Port number in config file should be greater than 1024, and less than 65536");
            }

            server_arr[counter].mtu = mtu;
            server_arr[counter].winsz = winsz;
            server_arr[counter].in_file_path = in_file_path;
            server_arr[counter].out_file_path = out_file_path;

            // std::cout << "ip addr: " << ip_addr << " port: " << port << '\n';

            counter++;

        }
    }else{
        error_and_exit("Couldn't open config file for reading");
    }

    return server_arr;
}

server_info* get_commandline_args(int argc, char** argv){

    server_info info;
    string conf_file;

    if(argc != 7){
        cerr << "Incorrect number of command line arguments.\nFormat: ./myclient servn servaddr.conf mtu winsz in_file_path out_file_path\n";
        exit(EXIT_FAILURE);
    }

    //check if servn is integer
    char* p;
    long converted_port = strtol(argv[1], &p, 10);
    if (*p) {
        error_and_exit("Please use a numerical servn number");
    }
    else {
        servn = converted_port;
    }

    conf_file = argv[2];

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
        in_file_path_global = argv[5];
    }

    //copy outfile into struct. Send to server so that it can create the path
    info.out_file_path = argv[6];


    //parse config file and returnn array of server information
    server_info* server_arr = parse_config(conf_file, servn, info.mtu, info.winsz, info.in_file_path, info.out_file_path);

    return server_arr;

}

void print_info(server_info* server_arr){
    for (int i = 0; i < servn; i++) {
        cout << "####### Server " << i << " #######\n";
        cout << "Server IP: " << server_arr[i].server_IP << "\n";
        cout << "Server Port: " << server_arr[i].server_port << "\n";
        cout << "MTU: " << server_arr[i].mtu << "\n";
        cout << "Winsz: " << server_arr[i].winsz << "\n";
        cout << "in file path: " << server_arr[i].in_file_path << "\n";
        cout << "out file path: " << server_arr[i].out_file_path << "\n";
        cout << "\n";
    }
    return;
}

void print_thread_args(thread_arguments thread_arguments){
    cout << "####### Thread args #######\n";
    cout << "Server IP: " << thread_arguments.info.server_IP << "\n";
    cout << "Server Port: " << thread_arguments.info.server_port << "\n";
    cout << "MTU: " << thread_arguments.info.mtu << "\n";
    cout << "Winsz: " << thread_arguments.info.winsz << "\n";
    cout << "in file path: " << thread_arguments.info.in_file_path << "\n";
    cout << "out file path: " << thread_arguments.info.out_file_path << "\n";
    cout << "basesn: " << thread_arguments.globals.basesn << "\n";
    cout << "nextsn: " << thread_arguments.globals.nextsn << "\n";
    cout << "basesn_packet_resent_number: " << thread_arguments.globals.basesn_packet_resent_number << "\n";
    cout << "last_ack: " << thread_arguments.globals.last_ack << "\n";
    cout << "\n";
    return;
}


socket_info connect_to_socket(server_info info){

    struct socket_info sockinfo;
    int sockfd;

    //create udp socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        error_and_exit("Error creating socket");
    }

    // bind socket to a random free port
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(0);
    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        close(sockfd);
        error_and_exit("Error binding socket");
    }

    // obtain local address and port number
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(sockfd, (struct sockaddr*)&local_addr, &local_addr_len) < 0) {
        close(sockfd);
        error_and_exit("Error getting local address");
    }

    //set server address and port number
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(info.server_port);

    //convert string IP address to binary equivalent
    if(inet_pton(AF_INET, info.server_IP.c_str(), &servaddr.sin_addr) <= 0){
        error_and_exit("Error converting string IP to binary");
    }

    sockinfo.sockfd = sockfd;
    sockinfo.local_port = ntohs(local_addr.sin_port);
    sockinfo.servaddr = servaddr;

    return sockinfo;
}

int check_and_open_in_file(string in_file_path){
    struct stat sb;

    if (stat(in_file_path.c_str(), &sb) == -1) {
        error_and_exit("stat() error");
    }
    else { //success finding size of file
        // cout << "In file size: " << (long long) sb.st_size << " bytes\n";
        in_file_size = (long long) sb.st_size;
    }

    int in_fd;
    in_fd = open(in_file_path.c_str(), O_RDONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if(in_fd < 0){
        error_and_exit("Error opening file at in_file_path");
    }
    return in_fd;
}

void log_time(string ack_or_data, thread_arguments thread_args, int seq_num, int winsz){


    // Get the current time
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::chrono::microseconds now_microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());

    // Generate RFC 3339 time string
    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", std::gmtime(&now_time_t));
    std::sprintf(buffer + 19, ".%03dZ", (int)(now_microseconds.count() % 1000000) / 1000);

    //lock so two threads cant print at the same time
    pthread_mutex_lock(&mutex);

    //print log line
    std::cout << buffer << ", " << thread_args.sockinfo.local_port << ", " << thread_args.info.server_IP << ", "
    << thread_args.info.server_port << ", " << ack_or_data << ", " << seq_num << ", " 
    << thread_args.globals.basesn << ", " << thread_args.globals.nextsn << ", " << thread_args.globals.basesn+winsz << "\n";

    //unlock crit section so other threads can print
    pthread_mutex_unlock(&mutex);

    return;
}

void print_message(string message, int port, int mode){

    //lock so two threads cant print at the same time
    pthread_mutex_lock(&mutex);

    //regular message 
    if(mode == 0){
        cerr << message;
    }

    //transfer complete
    if(mode == 1){
        cerr << "##### File Transfer Complete For Server Port: " << port << " #####\n";
    }

    //unlock crit section so other threads can print
    pthread_mutex_unlock(&mutex);

    return;
}

//########################### Client Processing ###########################

int end_transmission(int sockfd, sockaddr_in pservaddr, socklen_t servlen, string out_file_path){

    int s = 0;
    char ackbuffer[5000];
    bzero(&ackbuffer, sizeof(ackbuffer));
    string packet;
    packet = "ENDER_PACKET\r\n\r\nout_file_path: ";
    packet.append(out_file_path);

    s = sendto(sockfd, packet.c_str(), 5000, 0, (struct sockaddr*)&pservaddr, servlen);
    if(s < 0){
        error_and_exit("sendto() failed.");
    }

    recvfrom(sockfd, ackbuffer, 5000, 0, NULL, NULL);

    std::size_t found = string(ackbuffer).find("ENDER ACK");
    if (found==std::string::npos){
        return 0;
    }else{
        return 1;
    }

    return 1;

}

void send_client_info_to_server(int sockfd, sockaddr_in pservaddr, socklen_t servlen, string out_file_path){

    int n = 0;
    int s = 0;
    struct timeval tv;
    tv.tv_sec = 60; //60s timeout
    tv.tv_usec = 0;
    char ackbuffer[5000];
    bzero(&ackbuffer, sizeof(ackbuffer));
    string packet;
    // cout << "sending header packet...\n";
    packet = "INFORMATION_PACKET_ID\r\n\r\nout_file_path: ";
    packet.append(out_file_path);
    packet.append("\r\n\r\nbytes_in_file: ");
    string in_file_size_str = to_string(in_file_size);
    packet.append(in_file_size_str);
    // cout << packet << "\n";
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); //set timeout 
    s = sendto(sockfd, packet.c_str(), 5000, 0, (struct sockaddr*)&pservaddr, servlen);
    if(s < 0){
        error_and_exit("sendto() failed.");
    }

    n = recvfrom(sockfd, ackbuffer, 5000, 0, NULL, NULL);

    // cout << ackbuffer << "\n";

    if(n < 0){
        if(errno == EINTR){
            //interrupted call
            return;
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

thread_arguments handle_timeout(thread_arguments thread_args1, list<packet_info> window, int sockfd, sockaddr_in pservaddr, socklen_t servlen, string out_file_path, int winsz){

    struct thread_arguments thread_args = thread_args1;

    int closed_server = 0;
    int num_tries = 0;
    print_message("Packet loss detected\n", 0, 0);
    // cout << "basesn: " << basesn << " nextsn: " << nextsn << " basesn_packet_resent_number: " << basesn_packet_resent_number << " window.front().seq_num: " << window.front().seq_num << "\n";

    thread_args.globals.new_seq_num = window.front().seq_num;

    if(thread_args.globals.new_seq_num == thread_args.globals.old_seq_num){
        thread_args.globals.basesn_packet_resent_number++;
        if(thread_args.globals.basesn_packet_resent_number == 8){
            while(closed_server == 0){
                //let server know we failed
                closed_server = end_transmission(sockfd, pservaddr, servlen, out_file_path);
                num_tries++;
                if(num_tries > 10){
                    break;
                }
            }
            error_and_exit("Reached max re-transmission limit");
        }
    }else{
        thread_args.globals.basesn_packet_resent_number = 0;
    }

    int s;
    // cout << "re-sending packets in window. Basesn should be: " << basesn << " basesn IS: " << window.front().seq_num << " nextsn: " << nextsn << " window size: " << window.size() << "\n";
    for (auto const &i: window) {
        // cout << "packet seq: " << i.seq_num << "\n";
        log_time("DATA", thread_args, i.seq_num, winsz);
        s = sendto(sockfd, i.packet.c_str(), i.bytes_in_packet, 0, (struct sockaddr*)&pservaddr, servlen);
        if(s < 0){
            error_and_exit("sendto() failed.");
        }
    }

    thread_args.globals.old_seq_num = thread_args.globals.new_seq_num;

    return thread_args;
}


void do_client_processing(thread_arguments thread_args1, int in_fd, int sockfd, sockaddr_in pservaddr, socklen_t servlen, int mtu, int winsz, string out_file_path){

    struct thread_arguments thread_args = thread_args1;

    if(overhead_len >= mtu){ //check mtu can at least send one byte with overhead
        error_and_exit("Required minimum MTU is 61");
    }else if(mtu >= 32000){ //check that the mtu is less than 32000
        error_and_exit("MTU must be less than 32000");
    }

    //send information about the file thats about to be sent, including the out file path that the server needs to make
    send_client_info_to_server(sockfd, pservaddr, servlen, out_file_path);
    //TODO: wait for ack and retransmit if needed

    //init timer
    struct timeval tv1;
    tv1.tv_sec = 0; 
    tv1.tv_usec = 80000;

    int s;
    int n;
    int ack_n;
    int ack_seq_num = 0;
    char data[mtu-overhead_len+1];
    int packet_num = 0;
    char first_part[overhead_len+1];
    int bytes_in_packet = 0;
    int done_reading = 0;
    int old_basesn = 0;
    int closed_server = 0;

    bzero(&first_part, sizeof(first_part));
    bzero(&data, sizeof(data));

    string packet;
    char ack_buffer[2048];

    list<packet_info> window;

    //while the last ack has not been received from server, keep sending packets and looking for acks
    while (thread_args.globals.last_ack != 1) {
        
        while((thread_args.globals.nextsn < thread_args.globals.basesn+winsz) && done_reading == 0){

            //construct new packet and send off
            n = read(in_fd, data, mtu-overhead_len); //splits file into mtu-overhead sized chunks
            thread_args.globals.bytes_read_from_in_file += n;
            if(n < 0){
                error_and_exit("Read() error");
            }
            if(n == 0){ //eof
                done_reading = 1;
                break;
            }

            if(n != 0){

                struct packet_info new_packet;
                //prepare packet by adding overhead and data payload
                bytes_in_packet = sprintf(first_part, "\r\n\r\nPacket Num: %d\r\n\r\nLen: %d\r\n\r\nPayload:\n", packet_num, n);
                bytes_in_packet += n; //add bytes from data portion
                packet = first_part;
                packet.append(data, n);

                //add packet to window
                new_packet.bytes_in_packet = bytes_in_packet;
                new_packet.packet = packet;
                new_packet.seq_num = packet_num;

                window.push_back(new_packet);

                // send packet to server
                // cout << "sending packet: " << packet_num << " num bytes in payload: " << n << "\n";

                
                //log to stdout
                log_time("DATA", thread_args, packet_num, winsz);

                s = sendto(sockfd, packet.c_str(), bytes_in_packet, 0, (struct sockaddr*)&pservaddr, servlen);
                if(s < 0){
                    error_and_exit("sendto() failed.");
                }

                //increment nextsn
                thread_args.globals.nextsn++;

                packet_num++;
            }

        }

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv1, sizeof(tv1)); //set timeout 
        ack_n = recvfrom(sockfd, ack_buffer, 2048, 0, NULL, NULL);

        //got a packet
        if(ack_n != -1){
            sscanf(ack_buffer, "%*s %d %*s %d", &ack_seq_num, &thread_args.globals.last_ack);
            // cout << "Got ack for seq num: " << ack_seq_num << " last ack: " << thread_args.globals.last_ack << "\n";
            if(thread_args.globals.last_ack == 1){
                int num_tries = 0;
                print_message(" ", thread_args.info.server_port, 1);
                while(closed_server == 0){
                    //let server know we're done
                    closed_server = end_transmission(sockfd, pservaddr, servlen, out_file_path);
                    num_tries++;
                    if(num_tries > 10){
                        break;
                    }
                }
                break;
            }

            old_basesn = thread_args.globals.basesn;
            
            //when we get ack we need to slide window
            if(ack_seq_num >= thread_args.globals.basesn){
                thread_args.globals.basesn = ack_seq_num + 1;
            }

            //pop entries from window
            for(int i = 0; i < thread_args.globals.basesn-old_basesn; i++){
                window.pop_front();
            }

            //log to stdout
            log_time("ACK", thread_args, ack_seq_num, winsz);

        }

        if(ack_n < 0){
            if(errno == EINTR){
                //interrupted call
                // cout << "interrupted call\n";
            }else if(errno == EAGAIN){
                //server timed out
                thread_args = handle_timeout(thread_args, window, sockfd, pservaddr, servlen, out_file_path, winsz);
            }else if(errno == EWOULDBLOCK){
                //server timed out
                thread_args = handle_timeout(thread_args, window, sockfd, pservaddr, servlen, out_file_path, winsz);
            }else{
                //other recvfrom error
                cerr << "recvfrom() failed\n";
            }
        }
        
        bytes_in_packet = 0;
        packet.clear(); 
        bzero(&ack_buffer, sizeof(ack_buffer));
        bzero(&first_part, sizeof(first_part));
        bzero(&data, sizeof(data)); //zero out data for next read
        // cout << "port: " << thread_args.info.server_port << " basesn: " << thread_args.globals.basesn << " nextsn: " << thread_args.globals.nextsn << "\n";
    }

    close(in_fd);

}

void* threadTask(void* args) {
    struct thread_arguments thread_args = *(struct thread_arguments*)args;
    int in_fd = check_and_open_in_file(in_file_path_global); //returns fd for given in file
    socket_info socketinfo = connect_to_socket(thread_args.info); //returns information about server socket
    thread_args.sockinfo = socketinfo;
    do_client_processing(thread_args, in_fd, socketinfo.sockfd, socketinfo.servaddr, sizeof(socketinfo.servaddr), thread_args.info.mtu, thread_args.info.winsz, thread_args.info.out_file_path);
    pthread_exit(NULL);
}

int main(int argc, char** argv){

    //get command line arguments
    server_info* server_arr = get_commandline_args(argc, argv);
    // print_info(server_arr);

    //create a new thread_args structure with server_info[i] and fresh set of globals
    thread_arguments args[servn];
    thread_globals globals[servn];
    for(int i = 0; i < servn; i++) {
        args[i].info = server_arr[i];
        args[i].globals = globals[i];
    }

    //create servn number of threads
    pthread_t threads[servn];
    int rt_create;
    for (int i = 0; i < servn; i++) {
        //create threads and send to thread function
        // cout << args[i].info.server_port << "\n";
        rt_create = pthread_create(&threads[i], NULL, threadTask, &args[i]);
        if(rt_create != 0){
            error_and_exit("error creating threads");
        }
    }

    //join those threads
    int rt_join;
    for (int i = 0; i < servn; i++) {
        rt_join = pthread_join(threads[i], NULL);
        if(rt_join != 0){
            error_and_exit("error joining threads");
        }
    }

    //A few debugging printouts before exiting:
    // cout << "\n\nBytes read from in file: " << bytes_read_from_in_file << "\n";
    // cout << "In file size: " << in_file_size << "\n";
    delete[] server_arr;
    // close(in_fd); //close in file once we're done with everything
    return 0;
}