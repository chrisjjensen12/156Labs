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
#include <list>
#include <signal.h>
#include <sys/time.h>
#include <iterator>
#include <locale>
#include <ctime>
#include <unordered_map>
#include <csignal>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/ssl.h>
#include <openssl/err.h> 
#include <netdb.h>
#include <chrono>
#include <iomanip>

#define REQUEST_SIZE 65535
#define RESPONSE_SIZE 65535

using namespace std;

struct commmandline_args{
    int listen_port;
    pair<string, int> forbidden_sites_file;
    pair<string, int> log_file;
};

struct client_request_values{
    string method;
    string request_line;
    string host;
    string port;
    int error = 0;
};

struct client_request_info{
    char client_request[REQUEST_SIZE];
    int number_of_bytes;
    int client_socket;
    char client_ip[INET_ADDRSTRLEN];
};

//globals:
//hashmap for forbidden websites
std::unordered_map<std::string, bool> hashTable(1000);
//commandline arguments
commmandline_args args;
//mutex for shared hashmap
pthread_mutex_t hash_table_mutex = PTHREAD_MUTEX_INITIALIZER;
//server socket global
int server_socket;
//forbidden sites list global version number:
int version_number_global;
//mutex for log file
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

//flag to stop threads
volatile sig_atomic_t stop_flag = 0;

#define NUM_THREADS 50

typedef struct {
    int task_id;
    void (*function)(client_request_info, int);
    client_request_info arg;
} Task;

// Define a queue to hold the tasks
Task* task_queue[100];
int task_count = 0;
pthread_mutex_t task_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_available_cond = PTHREAD_COND_INITIALIZER;

//function declarations
void write_to_logfile(int response_size, string client_ip, string request_line, int status_code);


//########################### Helper Functions ###########################

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

void exit_thread(string print_error){

    int errnum;
    errnum = errno;

    if(errnum != 0){
        cerr << print_error << "\n" << "errno: " << errnum << "\n";
    }else{
        cerr << print_error << "\n";
    }

    pthread_exit(NULL);

    return; 
}

int check_and_open_file(string file_path, int mode){
    int fd;

    //mode 0 is read only
    if(mode == 0){
        fd = open(file_path.c_str(), O_RDONLY | O_CREAT);
        if(fd < 0){
            error_and_exit("Error opening file");
        }  
    }

    //mode 1 is write
    if(mode == 1){
        fd = open(file_path.c_str(), O_WRONLY | O_CREAT | O_APPEND);
        if(fd < 0){
            error_and_exit("Error opening file");
        }  
    }

    return fd;
}

void update_forbidden_sites(int fd){

    char buf[1024];
    std::string line;

    // Clear the hash table for new updates
    hashTable.clear();

    while (true) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == -1) {
            std::cerr << "Error reading file\n";
            return; //dont do anything just return
        } else if (n == 0) {
            // End of file
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                if (!line.empty()) {
                    //insert site/ip into the hash map
                    if(hashTable.size() != 1000){
                        hashTable[line] = true;
                    }
                }
                line.clear();
            } else {
                line.push_back(buf[i]);
            }
        }
    }
    if (!line.empty()) {
        //insert site/ip into the hash map
        if(hashTable.size() != 1000){
            hashTable[line] = true;
        }
    }

    // Reset file pointer to beginning
    lseek(fd, 0, SEEK_SET);

    return;

}

bool find_in_hashtable(string search_key){

    pthread_mutex_lock(&hash_table_mutex);

    if (hashTable.find(search_key) != hashTable.end()) {
        std::cerr << search_key << " exists in the forbidden sites file. Exiting now." << std::endl;
        pthread_mutex_unlock(&hash_table_mutex);
        return true;
    }
    else {
        std::cerr << search_key << " does not exist in the forbidden sites file. Continuing service." << std::endl;
        pthread_mutex_unlock(&hash_table_mutex);
        return false;
    }

    pthread_mutex_unlock(&hash_table_mutex);
    return true;

}

commmandline_args get_commandline_args(int argc, char** argv){

    commmandline_args args;

    //check if theres the right number of command line args
    if(argc != 4){
        error_and_exit("Incorrect number of arguments. Format: ./myproxy listen_port forbidden_sites_file_path access_log_file_path");
    }

    //get listen port and check if port is integer
    char* p;
    long converted_port = strtol(argv[1], &p, 10);
    if (*p) {
        error_and_exit("Please use a numerical port number");
    }
    else {
        args.listen_port = converted_port;
        // cout << args.listen_port << "\n";
    }

    //error check port
    if(args.listen_port <= 1024){
        error_and_exit("Port number should be greater than 1024, and less than 65536");
    }else if(args.listen_port >= 65536){
        error_and_exit("Port number should be greater than 1024, and less than 65536");
    }

    //get forbidden sites file path
    args.forbidden_sites_file.first = argv[2];

    //get access log file path
    args.log_file.first = argv[3];

    //attempt to open both files
    args.forbidden_sites_file.second = check_and_open_file(args.forbidden_sites_file.first, 0); //open forbidden sites file for reading
    args.log_file.second = check_and_open_file(args.log_file.first, 1); //open log file for writing

    //update hash table with names of all websites in forbidden sites file, pass in fd of file
    update_forbidden_sites(args.forbidden_sites_file.second);

    return args;
}

void send_response(int client_socket, int status_code, string client_ip, string request_line) {
    char response[1024];
    char status_message[30];

    // Construct the status message
    switch (status_code) {
        case 200:
            strcpy(status_message, "OK");
            break;
        case 400:
            strcpy(status_message, "Bad Request");
            break;
        case 403:
            strcpy(status_message, "Forbidden");
            break;
        case 501:
            strcpy(status_message, "Not Implemented");
            break;
        case 502:
            strcpy(status_message, "Bad Gateway");
            break;
        case 504:
            strcpy(status_message, "504 Gateway Timeout");
            break;
        case 500:
            strcpy(status_message, "Internal Server Error");
            break;
        default:
            strcpy(status_message, "Unknown");
            break;
    }

    // Construct the HTTP response message
    snprintf(response, sizeof(response), "HTTP/1.1 %d %s\r\n"
            "Server: myproxy156\r\n"
            "Connection: close\r\n\r\n", status_code, status_message);

    // Send the HTTP response message to the client socket
    send(client_socket, response, strlen(response), 0);

    write_to_logfile(strlen(response), client_ip, request_line, status_code);
}

void print_info(client_request_values request){
    cout << "Request line: " << request.request_line << endl;
    cout << "Host: " << request.host << endl;
    cout << "Method: " << request.method << endl;
    cout << "Port: " << request.port << endl;
}

//########################### Thread Pool ###########################

// Function to add a task to the queue
void add_task(Task* task) {
    pthread_mutex_lock(&task_queue_mutex);
    task_queue[task_count++] = task;
    pthread_cond_signal(&task_available_cond);
    pthread_mutex_unlock(&task_queue_mutex);
}

// Function to get the next task from the queue
Task* get_task() {
    Task* task = NULL;
    pthread_mutex_lock(&task_queue_mutex);
    while (task_count == 0 && !stop_flag) {
        pthread_cond_wait(&task_available_cond, &task_queue_mutex);
    }
    if (task_count > 0) {
        task = task_queue[--task_count];
    }
    pthread_mutex_unlock(&task_queue_mutex);
    return task;
}

// Function that each thread will run to wait for tasks
void* thread_func(void* arg) {

    // Block the control C signal in this thread
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    Task* task;
    while ((task = get_task()) != NULL) {
        // cout << "working on task number: " << task->task_id << endl;
        task->function(task->arg, version_number_global);
        free(task);
    }
    pthread_exit(NULL);
}

//########################### Signal Handlers ###########################

// signal handler function
void signal_handler_C(int signal_num) {
    cerr << "got control C, updating file now" << endl;

    pthread_mutex_lock(&hash_table_mutex);

    update_forbidden_sites(args.forbidden_sites_file.second);
    version_number_global++; //update global version number

    pthread_mutex_unlock(&hash_table_mutex);
}

// Define the signal handler function
void signal_handler_Q(int signum) {
    cerr << "Got SIGQUIT, setting flag and exiting now" << endl;
    stop_flag = 1;
    //close server socket so we don't get stuck on accept() or recv()
    close(server_socket);
    pthread_cond_broadcast(&task_available_cond);
}

void write_to_logfile(int response_size, string client_ip, string request_line, int status_code){
    
    pthread_mutex_lock(&log_mutex);
    // Get the current time
    auto now = std::chrono::system_clock::now();
    std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);
    std::chrono::microseconds now_microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());

    // Generate RFC 3339 time string
    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", std::gmtime(&now_time_t));
    std::sprintf(buffer + 19, ".%03dZ", (int)(now_microseconds.count() % 1000000) / 1000);

    char output[2000];
    sprintf(output, "%s %s \"%s\" %d %d\n", buffer, client_ip.c_str(), request_line.c_str(), status_code, response_size);

    write(args.log_file.second, output, strlen(output));

    pthread_mutex_unlock(&log_mutex);

    return;
}

//########################### SSL Functions ###########################

//sets up ssl connection, sends request, gets response
int setup_SSL_connection(string host, string port, int client_socket, string original_client_request, string client_IP, int local_version_num, string request_line){

    int sockfd;
    char ipstr[INET6_ADDRSTRLEN];

    //setup
    cerr << "setting up SSL library\n";
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *sslctx = SSL_CTX_new(SSLv23_method());
    if (!sslctx) {
        cerr << "SSL_CTX_new error\n";
        send_response(client_socket, 500, client_IP, request_line); //send ssl error to client
        return -1;
    }

    cerr << "performing DNS lookup\n";
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    //perform DNS lookup
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
        cerr << "getaddrinfo error\n";
        send_response(client_socket, 502, client_IP, request_line);
        return -1;
    }

    if (res == NULL) {
        cerr << "getaddrinfo: No addresses found for hostname" << endl;
        send_response(client_socket, 502, client_IP, request_line);
        return -1;
    }

    // loop through all the results and try to connect to each one
    for (p = res; p != NULL; p = p->ai_next) {
        // create a socket for this address
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("socket");
            continue; // try the next address
        }

        // try to connect to this address
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("connect");
            continue; // try the next address
        }

        // if we get here, we have successfully connected to an address
        break;
    }

    if (p == NULL) {
        // we were unable to connect to any of the addresses
        cerr << "We were unable to connect to any of the addresses" << endl;
        send_response(client_socket, 502, client_IP, request_line);
        return -1;
    }

    void *addr;
    if (p->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);
    }

    // convert the IP address to a string and print it out
    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
    cerr << "found ip address: " << ipstr << endl;
    

    cerr << "Looking for ip address in forbidden sites list\n";
    //look for ip on forbidden sites list
    if(find_in_hashtable(ipstr)){
        //if we found host in forbidden sites list
        send_response(client_socket, 403, client_IP, request_line);
        return -1;
    }

    cerr << "Establishing an SSL connection\n";
    // Establish SSL connection
    SSL *ssl = SSL_new(sslctx);
    if (!ssl) {
        cerr << "SSL_new error\n";
        send_response(client_socket, 500, client_IP, request_line); //send ssl error to client
        return -1;
    }
    if (SSL_set_fd(ssl, sockfd) == 0) {
        cerr << "SSL_set_fd error\n";
        send_response(client_socket, 500, client_IP, request_line); //send ssl error to client
        return -1;
    }
    if (SSL_connect(ssl) <= 0) {
        cerr << "SSL_connect error\n";
        send_response(client_socket, 500, client_IP, request_line); //send ssl error to client
        return -1;
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        cerr << "SSL_get_peer_certificate error\n";
        send_response(client_socket, 504, client_IP, request_line); //send ssl error to client
        return -1;
    }
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);

    cerr << "Writing request to server\n";
    //handshake done, now we can read/write bytes to connection
    if(!SSL_write(ssl, original_client_request.c_str(), strlen(original_client_request.c_str()))){ //write original request to ssl connection
        cerr << "SSL_write error\n";
        send_response(client_socket, 500, client_IP, request_line); //send ssl error to client
        return -1;
    } 

    int num_bytes;
    int total_bytes = 0;
    char buffer[RESPONSE_SIZE];
    int content_length = 0;
    bool chunked_encoding = false;
    bool got_content_length = false;
    bool is_head_request = false;
    int response_line_flag = 0;
    char response_line[500];
    char *content_length_ptr;
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    size_t found = original_client_request.find("HEAD");
    if (found != std::string::npos) {
        cerr << "found head request" << endl;
        is_head_request = true;
    } else {
        cerr << "not head request" << endl;
    }

    struct timeval timeout;
    timeout.tv_sec = 5; // set the timeout value to 5 seconds
    timeout.tv_usec = 0;

    cerr << "Receving response from server\n";
    while (1) {

        if(local_version_num != version_number_global){
            //time for another check
            if(find_in_hashtable(ipstr) || find_in_hashtable(host)){
                //if we found host or IP in forbidden sites list
                send_response(client_socket, 403, client_IP, request_line);
                return -1;
            }
            local_version_num = version_number_global; //we're good until the global changes again
        }
        
        int ret = select(sockfd + 1, &readfds, NULL, NULL, &timeout);

        if(ret == 0){
            //timeout, exit
            cerr << "timeout\n";
            break;
        }

        num_bytes = SSL_read(ssl, buffer, RESPONSE_SIZE);
        send(client_socket, buffer, num_bytes, 0);
        total_bytes += num_bytes;

        // Check if the response uses chunked encoding
        if (strstr(buffer, "Transfer-Encoding: chunked")) {
            chunked_encoding = true;
        }

        if(!got_content_length){
             // Parse the Content-Length header if it exists
            content_length_ptr = strstr(buffer, "Content-Length: ");
            if (content_length_ptr != NULL) {
                content_length = atoi(content_length_ptr + 16);
                got_content_length = true;
                memset(&content_length_ptr, 0, sizeof(content_length_ptr));
            }
        }

        // get response line
        if(response_line_flag == 0){
            for(int i = 0; i < num_bytes; i++){
                if(response_line_flag == 1){
                    break;
                }
                if(buffer[i+1] == '\r' && buffer[i+2] == '\n'){ //we got request line
                    response_line_flag = 1;
                }
                response_line[i] = buffer[i];
            }
        }

        // Break out of the loop once we have received the full response
        if (!chunked_encoding && total_bytes >= content_length) {
            cerr << "non chunked encoding message finished" << endl;
            break;
        }

        if(is_head_request){
            if(strstr(buffer, "\r\n\r\n")){
                cerr << "head request finished" << endl; 
                break;
            }
        }

        // cout << "loop" << endl;
        memset(&buffer, 0, sizeof(buffer));
    }

    if(chunked_encoding){
        cerr << "chunked encoding" << endl;
    }else{
        cerr << "content-length: " << content_length << endl;
    }

    int status_code = 0;

    sscanf(response_line, "%*s %d %*s", &status_code);

    write_to_logfile(total_bytes, client_IP, request_line, status_code);

    cerr << "Response finished, shutting down SSL connection\n\n";
    //shutdown
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    return 1;
}


//########################### Main Proxy Functions ###########################


client_request_values parse_request(string client_request, int client_socket, string client_ip){
    client_request_values request;

    // Parse the request message
    string method, path, version, host, request_line, url, port;

    // Find the end of the request line
    size_t request_line_end = client_request.find("\r\n");
    if (request_line_end != string::npos) {
        // Extract the request line
        request_line = client_request.substr(0, request_line_end);

        // Parse the request line
        size_t method_end = request_line.find(" ");
        size_t path_end = request_line.find(" ", method_end + 1);
        if (method_end != string::npos && path_end != string::npos){
            method = request_line.substr(0, method_end);
            url = request_line.substr(method_end + 1, path_end - method_end - 1);
            version = request_line.substr(path_end + 1);

            // Validate the parsed values
            if (method != "GET" && method != "HEAD") {
                //send 400 bad request and exit thread
                send_response(client_socket, 501, client_ip, request_line);
                request.error = 1;
                return request;
            }

            if (version != "HTTP/1.0" && version != "HTTP/1.1") {
                //send 400 bad request and exit thread
                send_response(client_socket, 400, client_ip, request_line);
                request.error = 1;
                return request;
            }
        } else {
            //send 400 bad request and exit thread
            send_response(client_socket, 400, client_ip, request_line);
            request.error = 1;
            return request;
        }
    }

    //get the host header
    size_t host_header_start = client_request.find("Host: ");
    if (host_header_start != string::npos) {
        // Extract the value of the host header
        size_t host_header_end = client_request.find("\r\n", host_header_start);
        if (host_header_end != string::npos) {
            host = client_request.substr(host_header_start + 6, host_header_end - host_header_start - 6);
        }
    }else{
        send_response(client_socket, 400, client_ip, request_line);
        request.error = 1;
        return request;
    }

    //get port number if it exists
    int num;
    size_t colon_pos = url.find(':', 6); // Start searching after the "://" (6 characters)
    if (colon_pos != string::npos) { //if we found a port
        size_t slash_pos = url.find('/', colon_pos + 1);
        port = url.substr(colon_pos + 1, slash_pos - colon_pos - 1);
        std::stringstream ss(port);
        if (ss >> num) {
            request.port = port;
        } else {
            send_response(client_socket, 400, client_ip, request_line);
            request.error = 1;
            return request;
        }
    }else{ //else default to port num 443
        request.port = "443";
    }

    request.request_line = request_line;
    request.method = method;
    request.host = host;

    return request;
}


void get_client_request(client_request_info info, int version_num) {
    int local_version_num = version_num; //get version number of forbidden sites log at the start of thread's job
    client_request_values request;
    // cout << "number of bytes in request: " << info.number_of_bytes << endl;
    // cout << info.client_request;

    //parse request and get needed variables
    request = parse_request(info.client_request, info.client_socket, info.client_ip);
    if(request.error == 1){ //if anything above errored, return to thread pool
        close(info.client_socket);
        return;
    }

    //look for host on forbidden sites list
    if(find_in_hashtable(request.host)){
        //if we found host in forbidden sites list
        send_response(info.client_socket, 403, info.client_ip, request.request_line);
        close(info.client_socket);
        return;
    }

    //give request to this function to setup SSL connection and convert HTTP to HTTPS
    int sslerror;
    sslerror = setup_SSL_connection(request.host, request.port, info.client_socket, info.client_request, info.client_ip, local_version_num, request.request_line);
    if(sslerror < 0){
        close(info.client_socket);
        return;
    }

    close(info.client_socket);
}


int listen_for_requests(){

    // Create a server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        error_and_exit("socket error");
    }

    // Bind the server socket to the given port
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(args.listen_port);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        error_and_exit("bind error");
    }
    if (listen(server_socket, 128) < 0) {
        error_and_exit("listen error");
    }

    int i;
    int task_num = 0;
    int completed_joins = 0;
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    // Create 50 threads
    for (i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, thread_func, &thread_ids[i])) {
            fprintf(stderr, "Error creating thread\n");
            exit(1);
        }
    }

    struct sockaddr_in client_address;
    socklen_t client_address_size = sizeof(client_address);
    int client_socket;
    char client_request[REQUEST_SIZE];
    int bytes_received = 0;

    while (stop_flag == 0) {
        // Accept a connection
        if(stop_flag == 0){
            client_socket = accept(server_socket, (struct sockaddr*) &client_address, &client_address_size);
            bytes_received = recv(client_socket, client_request, sizeof(client_request), 0);
            if(bytes_received < 0){
                close(client_socket);
                continue;
            }
        }

        //get client ip address 
        struct in_addr ipAddr = client_address.sin_addr;
        char str[INET_ADDRSTRLEN];
        inet_ntop( AF_INET, &ipAddr, str, INET_ADDRSTRLEN);
        // cout << "client ip: " << str << endl;

        //give the message from the client to the pool of worker threads
        if(stop_flag == 0){
            Task* task = (Task*) malloc(sizeof(Task));
            task->task_id = task_num;
            task->function = get_client_request;
            task->arg.number_of_bytes = bytes_received;
            task->arg.client_socket = client_socket;
            strcpy(task->arg.client_ip, str);
            strcpy(task->arg.client_request, client_request);
            add_task(task);
        }

        //clean up
        task_num++;
        bytes_received = 0;
        memset(client_request, 0, sizeof(client_request));
    }


    //shutdown the server and join the threads
    for (i = 0; i < NUM_THREADS; i++) {
        if(pthread_join(threads[i], NULL) == 0){
            completed_joins++;
        }
    }

    if(completed_joins == 50){
        //all threads joined
        cerr << "all threads joined\n";
    }

    return server_socket;
}

//########################### Main ###########################


int main(int argc, char** argv) {

    cerr << "PID (to manually terminate): " << getpid() << "\n" << endl;
    //signal handler for control C
    signal(SIGINT, signal_handler_C);

    //signal handler for SIGTERM sent from command line
    signal(SIGQUIT, signal_handler_Q);
    
    args = get_commandline_args(argc, argv);

    int server_socket = listen_for_requests();

    //close everything and clear out hash table
    close(server_socket);
    close(args.forbidden_sites_file.second);
    close(args.log_file.second);
    hashTable.clear();

    return 0;
}