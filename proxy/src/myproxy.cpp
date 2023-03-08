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

using namespace std;

struct commmandline_args{
    int listen_port;
    pair<string, int> forbidden_sites_file;
    pair<string, int> log_file;
};

struct client_request_values{
    string method;
    string host_name;
};

struct client_request_info{
    char client_request[65535];
    int number_of_bytes;
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

//flag to stop threads
volatile sig_atomic_t stop_flag = 0;

#define NUM_THREADS 50

typedef struct {
    int task_id;
    void (*function)(client_request_info);
    client_request_info arg;
} Task;

// Define a queue to hold the tasks
Task* task_queue[100];
int task_count = 0;
pthread_mutex_t task_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_available_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t client_recv_mutex = PTHREAD_MUTEX_INITIALIZER;

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

    if (hashTable.find(search_key) != hashTable.end()) {
        std::cout << search_key << " exists in the hash table." << std::endl;
        return true;
    }
    else {
        std::cout << search_key << " does not exist in the hash table." << std::endl;
        return false;
    }

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
    Task* task;
    while ((task = get_task()) != NULL) {
        task->function(task->arg);
        free(task);
    }
    pthread_exit(NULL);
}

//########################### Signal Handlers ###########################

// signal handler function
void signal_handler_C(int signal_num) {
    cout << "got control C, updating file now" << endl;

    pthread_mutex_lock(&hash_table_mutex);

    update_forbidden_sites(args.forbidden_sites_file.second);

    pthread_mutex_unlock(&hash_table_mutex);
}

// Define the signal handler function
void signal_handler_Q(int signum) {
    cout << "Got SIGQUIT, setting flag and exiting now" << endl;
    stop_flag = 1;
    //close server socket so we don't get stuck on accept() or recv()
    close(server_socket);
    pthread_cond_broadcast(&task_available_cond);
}


//########################### Main Proxy Functions ###########################
// client_request_values parse_request(string client_request){
//     client_request_values request;

//     // Parse the request message
//     string method, path, version, host;

//     // Find the end of the request line
//     size_t request_line_end = client_request.find("\r\n");
//     if (request_line_end != string::npos) {
//         // Extract the request line
//         string request_line = client_request.substr(0, request_line_end);

//         // Parse the request line
//         size_t method_end = request_line.find(" ");
//         size_t path_end = request_line.find(" ", method_end + 1);
//         if (method_end != string::npos && path_end != string::npos){
//             method = request_line.substr(0, method_end);
//             path = request_line.substr(method_end + 1, path_end - method_end - 1);
//             version = request_line.substr(path_end + 1);

//             // Validate the parsed values
//             if (method != "GET" && method != "HEAD") {
//                 //send 400 bad request and exit thread
//                 exit_thread("sending 400 bad request");
//             }

//             if (version != "HTTP/1.0" && version != "HTTP/1.1") {
//                 //send 400 bad request and exit thread
//                 exit_thread("sending 400 bad request");
//             }
//         } else {
//             //send 400 bad request and exit thread
//             exit_thread("sending 400 bad request");
//         }
//     }

//     cout << "method: " << method << " path: " << path << " version: " << version << "\n";


//     return request;
// }


void get_client_request(client_request_info info) {

    cout << "number of bytes in request: " << info.number_of_bytes << endl;
    cout << info.client_request;

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
    char client_request[65535];
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
            close(client_socket);
        }

        //give the message from the client to the pool of worker threads
        if(stop_flag == 0){
            Task* task = (Task*) malloc(sizeof(Task));
            task->task_id = task_num;
            task->function = get_client_request;
            task->arg.number_of_bytes = bytes_received;
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
        cout << "all threads joined\n";
    }

    return server_socket;
}

int main(int argc, char** argv) {
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