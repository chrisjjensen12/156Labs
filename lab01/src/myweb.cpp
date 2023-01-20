#include <iostream>
#include <string.h>
#include <iostream>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <unistd.h>
#include <bits/stdc++.h>

using namespace std;

#define DEFAULT_PORT 80
#define BUFFERLENGTH 4096

struct request {
    string hostname;
    string IP_address;
    uint16_t port_num;
    string document_path;
    bool header_flag = false;
    bool is_there_a_port = false;
};

struct response_header_info {
    int message_body_index;
    int content_length = 0;
    int found_content_length;
    int status_code;
};

request parse_url_path(request request1, string URLpath){
    request return_request = request1;
    string portstr;
    string IP_with_port;
    //get ip address (w/port)
    string delimiter = "/";
    IP_with_port = URLpath.substr(0, URLpath.find(delimiter));
    //get port num (if exists)
    if(IP_with_port.find(':') != std::string::npos){
        delimiter = ":";
        portstr = IP_with_port.substr(IP_with_port.find(":")+1, IP_with_port.find("/"));
        return_request.IP_address = IP_with_port.substr(0, IP_with_port.find(":"));
        return_request.port_num = stoi(portstr); //convert string port to integer
        // if(return_request.port_num != DEFAULT_PORT){
        //     cout << "Error: port not supported" << "\n";
        //     exit(0);
        // }
    }else{
        return_request.IP_address = URLpath.substr(0, URLpath.find("/"));
        return_request.port_num = DEFAULT_PORT;
    }
    //get document path
    return_request.document_path = URLpath.substr(URLpath.find("/")+1, URLpath.length());

    return return_request;
}

request get_commandline_args(int argc, char** argv){
    request request1;

    if(argc > 2){ //gets hostname and url path
        request1.hostname = argv[1];
        request1 = parse_url_path(request1, argv[2]);
    }else{
        cerr << "Error: Missing Necessary Command Line Arguments" << "\n";
        exit(0);
    }
    if(argc > 3 && strcmp(argv[3], "-h") != 0){ //if there is a third command line argument and it is not -h, exit
        cerr << "Error: Third command line argument not supported" << "\n";
        exit(0);
    }else{
        if(argc < 4){
            request1.header_flag = false;
        }else{
            request1.header_flag = true;
        }
    }

    return request1;
}

void print_request(request request1){
    cout << "Hostname: " << request1.hostname << "\n";
    cout << "IP Address: " << request1.IP_address << "\n";
    cout << "Port: " << request1.port_num << "\n";
    cout << "Document Path: " << request1.document_path << "\n";
    if(request1.header_flag == false){
        cout << "Header Flag?: " << "No" << "\n";
    }else{
        cout << "Header Flag?: " << "Yes" << "\n";
    }

    return;
}

void error_and_exit(string print_error){

    int errnum;
    errnum = errno;
    cerr << print_error << "\n" << "errno: " << errnum << "\n";

    exit(0); 
}

response_header_info process_headers(char * char_arr_headers, bool header_flag){

    response_header_info response_info;

    string headers = char_arr_headers;

    if(header_flag == true){ //print headers if -h flag and exit
        cout << headers;
        exit(0);
    }

    // Vector of string to save tokens
    vector <string> tokens;
     
    // stringstream class check1
    stringstream check1(headers);
     
    string intermediate;
    
    while(getline(check1, intermediate, '\n')){
        tokens.push_back(intermediate);
    }

    int status_code = 0;
    int content_length = 0;
    int found_content_length = 0;
    char chunked_encoding[50];
    // Printing the token vector (list of headers)
    for(int i = 0; i < (int)tokens.size(); i++){
        if(tokens[i].find("HTTP/1.1") != std::string::npos || tokens[i].find("HTTP/1.0") != std::string::npos){
            sscanf(tokens[i].c_str(), "%*s %d %*s", &status_code);
        }
        if(tokens[i].find("Content-Length:") != std::string::npos || tokens[i].find("content-length:") != std::string::npos){
            sscanf(tokens[i].c_str(), "%*s%d", &content_length);
            found_content_length = 1;
        }
        if(tokens[i].find("Transfer-Encoding:") != std::string::npos || tokens[i].find("transfer-encoding:") != std::string::npos){ //handle chunked encoding
            sscanf(tokens[i].c_str(), "%*s%s", chunked_encoding);
            if(strcmp(chunked_encoding, "chunked") == 0){
                cerr << "Chunked encoding is not supported" << "\nExiting now...\n";
                exit(0);
            }
        }
    }

    if(found_content_length == 1){
        response_info.found_content_length = 1;
    }else{
        response_info.found_content_length = 0;
    }

    // cout << "status code: "<< status_code << " content length: " << content_length << "\n";

    response_info.status_code = status_code;

    response_info.content_length = content_length;

    return response_info;
}


void send_request(request request1){

    //get socketfd
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketfd < 0){
        error_and_exit("Error creating socket");
    }

    //create socket address structure
    struct sockaddr_in socstruct;
    bzero(&socstruct, sizeof(socstruct)); //zero out struct
    socstruct.sin_family = AF_INET; //address family: internet address
    socstruct.sin_port = htons(request1.port_num); //converts from MY local byte order to network standard

    //convert string IP address to binary equivalent
    if(inet_pton(AF_INET, request1.IP_address.c_str(), &socstruct.sin_addr) <= 0){
        error_and_exit("Error converting string IP to binary");
    }

    //now connect to server
    if(connect(socketfd, (sockaddr *) &socstruct, sizeof(socstruct)) < 0){
        error_and_exit("Connection to server failed");
    }

    //create message to send
    char request_message[BUFFERLENGTH];
    if(request1.header_flag == false){ //no -h option
        sprintf(request_message, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", request1.document_path.c_str(), request1.hostname.c_str());
    }else{ 
        sprintf(request_message, "HEAD /%s HTTP/1.1\r\nHost: %s\r\n\r\n", request1.document_path.c_str(), request1.hostname.c_str());
    }

    // cout << request_message << "\n";

    //send message over socketfd
    int numbytes = strlen(request_message);
    if(write(socketfd, request_message, numbytes) != numbytes){
        error_and_exit("Error writing to socketfd");
    }

    //read incoming message
    char received_message[BUFFERLENGTH];
    int n = 0;
    int body_bytes_read = 0;
    int got_all_headers = 0;
    int header_index = 0;
    int copy_from_here_on = 0;
    char headers[8192];
    char end_of_headers[5] = "\r\n\r\n";
    response_header_info response_info;
    bzero(received_message,BUFFERLENGTH);
    ofstream myfile;
    myfile.open("output.dat");
    while ((n = read(socketfd, received_message, BUFFERLENGTH - 1)) >= 0){
        if(n < 0){
            error_and_exit("Read error");
        }
        if(got_all_headers == 0){ //get headers
            for(int i = 0; i < n; i++){
                headers[header_index] = received_message[i];
                header_index++;
                if(strstr(headers, end_of_headers) != NULL){
                    response_info = process_headers(headers, request1.header_flag);
                    // cout << headers;
                    // cout << "content length: " << response_info.content_length << " status code: " << response_info.status_code << "\n";
                    got_all_headers = 1;
                    break;
                }
            }
        }
        if(got_all_headers == 1){ //if already got headers, get body
            if(response_info.content_length == 0 && response_info.status_code != 200){
                cerr << "server responded with status code: " << response_info.status_code << " (no content length)\nExiting now...\n";
                myfile.close();
                close(socketfd);
                exit(0);
            }
            if(response_info.found_content_length == 0 && response_info.status_code != 200){
                cerr << "server responded with status code: " << response_info.status_code << "\nExiting now...\n";
                myfile.close();
                close(socketfd);
                exit(0);
            }
            for(int i = 0; i < n; i++){
                if(i == header_index && copy_from_here_on == 0){ //start at the end of the headers
                    copy_from_here_on = 1;
                }
                if(copy_from_here_on == 1){
                    myfile << received_message[i];
                    body_bytes_read++;
                    if(body_bytes_read == response_info.content_length){
                        myfile.close();
                        close(socketfd);
                        return;
                    }
                }
            }
        }
        bzero(received_message,BUFFERLENGTH); //zero out buffer
    }

    close(socketfd);
    myfile.close();
    return;
}
  
int main(int argc, char** argv)
{
    //get command line args and store in request struct
    request request1;
    request1 = get_commandline_args(argc, argv);

    // print_request(request1);
    
    send_request(request1);

    return 0;
}