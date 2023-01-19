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
    int content_length;
    int found_content_length;
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
        cout << "Error: Missing Necessary Command Line Arguments" << "\n";
        exit(0);
    }
    if(argc > 3 && strcmp(argv[3], "-h") != 0){ //if there is a third command line argument and it is not -h, exit
        cout << "Error: Third command line argument not supported" << "\n";
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

    cout << "bruh\n";

    int errnum;
    errnum = errno;
    cout << print_error << "\n" << "errno: " << errnum << "\n";

    exit(0); 
}

response_header_info process_headers(char * received_message, bool header_flag){

    //check status code to see if its 200
    string message = received_message;
    response_header_info response_info;
    string headers;
    if(message.find("\r\n\r\n") != std::string::npos){
        response_info.message_body_index = message.find("\r\n\r\n")+4; //starting index of body is at \r\n\r\n + 4
    }
    headers = message.substr(0, response_info.message_body_index);

    cout << headers;

    if(header_flag == true){
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
        if(tokens[i].find("Transfer-Encoding:") != std::string::npos){ //handle chunked encoding
            sscanf(tokens[i].c_str(), "%*s%s", chunked_encoding);
            if(strcmp(chunked_encoding, "chunked") == 0){
                cout << "Chunked encoding is not supported" << "\nExiting now...\n";
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

    //check if status code is 200, if not error code and exit
    if(status_code != 200){
        cout << headers;
        cout << "server responded with status code: " << status_code << "\nExiting now...\n";
        exit(0);
    }else{
        response_info.content_length = content_length;
    }

    return response_info;
}


void send_request(request request1){

    //get socketfd
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketfd < 0){
        error_and_exit("Error creating socket");
    }

    // print_request(request1);

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
    int bytes_read = 0;
    int body_bytes_read = 0;
    int processed_headers = 0;
    int copy_from_here_on = 0;
    response_header_info response_info;
    bzero(received_message,BUFFERLENGTH);
    ofstream myfile;
    myfile.open("output.dat");
    while ((n = read(socketfd, received_message, BUFFERLENGTH - 1)) > 0){
        if(n < 0){
            error_and_exit("Read error");
        }
        if(processed_headers == 0){
            response_info = process_headers(received_message, request1.header_flag);
            cout << "content length: " << response_info.content_length << " starting index: " << response_info.message_body_index << "\n";
            processed_headers = 1;
        }
        for(int i = 0; i < n; i++){
            if(response_info.found_content_length == 1){
                if(bytes_read == response_info.message_body_index && copy_from_here_on == 0){
                    bytes_read = -1; //reset bytes read to 0, so that it can start counting the message body length
                    copy_from_here_on = 1;
                }
                if(copy_from_here_on == 1){
                    if(body_bytes_read != response_info.content_length){
                        // printf("%c", received_message[i]);
                        myfile << received_message[i];
                        body_bytes_read++;
                        if(body_bytes_read == response_info.content_length){ //finished all body bytes, return to function
                            myfile.close();
                            close(socketfd);
                            return;
                        }
                    }
                }
            }else{
                //read everything into file until EOF.
                if(n == 0){
                    myfile.close();
                    close(socketfd);
                    return;
                }
                if(bytes_read == response_info.message_body_index && copy_from_here_on == 0){
                    copy_from_here_on = 1;
                }
                if(copy_from_here_on == 1){
                    myfile << received_message[i];
                }
            }
            // cout << "Bytes read: " << bytes_read << "\n";
            bytes_read++;
        }
        bzero(received_message,BUFFERLENGTH); //zero out buffer
    }

    myfile.close();
    return;
}
  
int main(int argc, char** argv)
{
    //get command line args and store in request struct
    request request1;
    request1 = get_commandline_args(argc, argv);

    print_request(request1);
    
    send_request(request1);

    return 0;
}
