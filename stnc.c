#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <sys/time.h>
// https://stackoverflow.com/questions/10324611/how-to-calculate-the-md5-hash-of-a-large-file-in-c

#define FILE_TO_SEND "FileToSend.txt"
#define FILE_TO_RECV "FileToRecv.txt"
#define MAX_MSG_LEN 1024
#define SIZE (100 * 1024 * 1024)
#define CHUNK_SIZE (100*1024)
#define BUF_SIZE 1024
#define BACKLOG 5
#define TCP4  1
#define TCP6  2 
#define UDP4  3 
#define UDP6  4 
#define UDGRM  5 
#define UDSTRM  6 
#define MMAP  7 
#define PIPE  8      
#define PORT_S 8888

// Globals
int sockfd = -1;
int port = 0;
int q = 0;
int gap = 0;
int test_performance = 0;
int flage = 0;
char* ip = NULL;
int is_server = 0;
int is_client = 0;
char* ip_s = NULL;
struct timeval start, end;
unsigned char client_hash[MD5_DIGEST_LENGTH] = {0};
unsigned short checksum_from_client;
unsigned char server_hash[MD5_DIGEST_LENGTH] = {0};
char hash_from_client[MD5_DIGEST_LENGTH * 2 + 1] = {0};
double time1 = 0;
double time2 = 0;
double time3 = 0;
double time4 = 0;


void print_usage() 
{
    printf("Usage: stnc [-c IP PORT -p TYPE PARAM | -s PORT -p -q]\nPlease put 0 in the empty spaces\n");
}



void client_generate_to_file()
{
    // Define a pointer to a new file.
    FILE *ptrF;
    ptrF = fopen(FILE_TO_SEND, "wb"); // Point to the specific file.
    if (ptrF == NULL)
    {
        printf("file can't be opened. \n");
    }

    int i;
    for (i = 0; i < SIZE; i++)
    {
        char c = (rand() % 255) + 1;
        fprintf(ptrF, "%c", c);
    }
    
    // Calculate the MD5 hash of the file
    EVP_MD_CTX *mdContext;
    const EVP_MD *md;
    unsigned char mdValue[EVP_MAX_MD_SIZE];
    unsigned int mdLen;
    
    md = EVP_md5(); // Choose MD5 as the hash function
    mdContext = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdContext, md, NULL);
    
    fseek(ptrF, 0, SEEK_SET); // Reset file pointer to the beginning
    while (1)
    {
        int bytesRead = fread(mdValue, 1, EVP_MAX_MD_SIZE, ptrF);
        if (bytesRead <= 0)
            break;
        EVP_DigestUpdate(mdContext, mdValue, bytesRead);
    }
    EVP_DigestFinal_ex(mdContext, client_hash, &mdLen);
    EVP_MD_CTX_free(mdContext);

    fclose(ptrF);
    return;
}

void server_generate_to_file()
{
    // Define a pointer to a new file.
    FILE *ptrF;
    ptrF = fopen(FILE_TO_RECV, "rb"); // Point to the specific file.
    if (ptrF == NULL)
    {
        printf("file can't be opened. \n");
    }    
    // Calculate the MD5 hash of the file
    EVP_MD_CTX *mdContext;
    const EVP_MD *md;
    unsigned char mdValue[EVP_MAX_MD_SIZE];
    unsigned int mdLen;
    
    md = EVP_md5(); // Choose MD5 as the hash function
    mdContext = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdContext, md, NULL);
    
    fseek(ptrF, 0, SEEK_SET); // Reset file pointer to the beginning
    while (1)
    {
        int bytesRead = fread(mdValue, 1, EVP_MAX_MD_SIZE, ptrF);
        if (bytesRead <= 0)
            break;
        EVP_DigestUpdate(mdContext, mdValue, bytesRead);
    }
    EVP_DigestFinal_ex(mdContext, server_hash, &mdLen);
    EVP_MD_CTX_free(mdContext);

    fclose(ptrF);
    return;
}




void call_server()
{
    struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            perror("bind");
            return;
        }
        if (listen(sockfd, 1) < 0)
        {
            perror("listen");
            return;
        }
        if(!q) {printf("Server started, listening on port %d...\n", port);}
        // Accept client connection
        struct sockaddr_in client_addr = {0};
        socklen_t client_addrlen = sizeof(client_addr);
        int client_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addrlen);
        if (client_sockfd < 0)
        {
            perror("accept");
            return;
        }
        if(!q) {printf("Client connected from %s:%d\n", inet_ntoa(client_addr.sin_addr), 		
        ntohs(client_addr.sin_port));}
        sockfd = client_sockfd;

        if (test_performance)
        {
            // Receive flage from client
            char msg_to_recv[1] = {0};
            int len = recv(sockfd, msg_to_recv, sizeof(msg_to_recv), 0);
            if (len < 0)
            {
                perror("recv1");
                return;
            }
            // Print received message
            flage = atoi(msg_to_recv);
            

            // Receive hash from client
            len = recv(sockfd, hash_from_client, MD5_DIGEST_LENGTH * 2 + 1, 0);
            if (len < 0)
            {
                perror("recv2");
                return;
            }
            
        }
}

void call_client()
{
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
    {
        perror("inet_pton");
        return;
    }
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        return;
    }
    if(!q) {printf("Connected to server at %s:%d\n", ip, port);}

    // Create the file with the data
    client_generate_to_file();

    if (test_performance)
    {
        char msg_to_send[10];
        sprintf(msg_to_send, "%d", flage);
        // Send flage to server
        if (send(sockfd, msg_to_send, sizeof(msg_to_send), 0) < 0)
        {
            perror("send1");
            return;
        }

        // Send hash to server
        if (send(sockfd, client_hash, sizeof(client_hash), 0) < 0)
        {
            perror("send2");
            return;
        }

    }
}

void start_chat()
{
    printf("start chating...\n");
    // Create pollfd array for monitoring input from keyboard and socket
    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO; // Keybord
    fds[0].events = POLLIN;
    fds[1].fd = sockfd; // Socket
    fds[1].events = POLLIN;

    // Main loop
    while (1)
    {
        // Wait for events on both the keyboard and the socket
        if (poll(fds, 2, -1) < 0)
        {
            perror("poll");
            return;
        }

        // Check for events on the keyboard
        if (fds[0].revents & POLLIN)
        {
            // Read input from keyboard
            char msg[MAX_MSG_LEN] = {0};
            if (fgets(msg, MAX_MSG_LEN, stdin) == NULL)
            {
                perror("fgets");
                return;
            }
            // Send message to server/client
            if (send(sockfd, msg, strlen(msg), 0) < 0)
            {
                perror("send");
                return;
            }
            printf("-> Me: %s", msg);
        }

        // Check for events on the socket
        if (fds[1].revents & POLLIN)
        {
            // Receive message from server/client
            char msg[MAX_MSG_LEN] = {0};
            int len = recv(sockfd, msg, MAX_MSG_LEN, 0);
            if (len < 0)
            {
                perror("recv");
                return;
            }
            else if (len == 0)
            {
                printf("Connection closed by remote side.\n");
                break;
            }
            // Print received message
            printf("-> Him: %s", msg);
        }
    }
    // Close socket
    close(sockfd);
    return;
}


void udp_ipv4_server()
{
    struct sockaddr_in server_addr; // client_addr
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
        perror("socket");
        exit(1);
    }
    // Set socket options
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT_S);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        perror("bind");
        exit(1);
    }


}
// global
int client_sock;    

void ipv6_server()
{
    struct sockaddr_in6 server_addr;
    struct sockaddr_in6 client_addr6;
    socklen_t client_addr_len = sizeof(client_addr6);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(PORT_S);
    server_addr.sin6_addr = in6addr_any;

    int domain = (flage == TCP6) ? SOCK_STREAM : SOCK_DGRAM;

    if ((sockfd = socket(AF_INET6, domain, 0)) == -1) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) 
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (flage == TCP6) 
    {
        if (listen(sockfd, BACKLOG) == -1) 
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        if ((client_sock = accept(sockfd, (struct sockaddr *)&client_addr6, &client_addr_len)) == -1) 
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }
    } 
}

void recv_data()
{
    struct sockaddr_in6 client_addr6;
    socklen_t client_addr_len6 = sizeof(client_addr6);
    int size_file = 0;
    gettimeofday(&start, NULL);
    FILE *ptrF;
    ptrF = fopen(FILE_TO_RECV, "wb"); // Point to the specific file.
    if (ptrF == NULL)
    {
        printf("file can't be opened. \n");
    } 
    int len = 0;
    socklen_t addrlen;
    struct sockaddr_in client_addr;
    char chunk_file[BUF_SIZE] = {0};
    addrlen = sizeof(client_addr);

    while (size_file < SIZE)
    {

        if (flage == UDP4 )
        {
            len = recvfrom(sockfd, chunk_file, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &addrlen);
        
        }
        else if (flage == TCP4)
        {
            len = recv(sockfd, chunk_file, BUF_SIZE, 0);
        
        }
        else if (flage == TCP6)
        {
            len = recvfrom( client_sock , chunk_file, BUF_SIZE, 0, (struct sockaddr *)&client_addr6, &client_addr_len6); 
        }
        else if( flage == UDP6)
        {
        	len = recvfrom(sockfd, chunk_file, BUF_SIZE, 0, (struct sockaddr *)&client_addr6, &client_addr_len6); 
        }
        if (len < 0)
        {
            perror("recvfrom");
            return;
        }
        
        size_file += len;
        
        // Write data to file
        fprintf(ptrF, "%s", chunk_file); 
        
        len = 0;
        //memset(&chunk_file, 0, sizeof(chunk_file));

    }
    
    if (flage == UDP4)
    {
        recvfrom(sockfd, chunk_file, BUF_SIZE, 0, NULL, NULL);
    }
    fclose(ptrF);
    
    gettimeofday(&end, NULL);
    time1 = (end.tv_sec - start.tv_sec) + (end.tv_usec - 
    start.tv_usec) / 1000000.0;
    
    server_generate_to_file();

}

// udp globals
struct sockaddr_in server_addr;
void udp_ipv4_client()
{
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
        perror("socket");
        exit(1);
    }
    // Set socket options
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT_S);
    server_addr.sin_addr.s_addr = inet_addr(ip_s);

}
struct sockaddr_in6 server_addr6;
void ipv6_client()
{
    

    memset(&server_addr6, 0, sizeof(server_addr6));
    server_addr6.sin6_family = AF_INET6;
    server_addr6.sin6_port = htons(PORT_S);
    
    if (inet_pton(AF_INET6, "::1", &server_addr6.sin6_addr) <= 0) 
    {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    int domain = (flage == TCP6) ? SOCK_STREAM : SOCK_DGRAM;

    if ((sockfd = socket(AF_INET6, domain, 0)) == -1) 
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (flage == TCP6) 
    {
        sleep(1);
        if(connect(sockfd, (struct sockaddr *)&server_addr6, sizeof(server_addr6)) == -1) 
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    }

}

void send_data(){
    
    FILE *ptrF;
    ptrF = fopen(FILE_TO_SEND, "rb"); // Point to the specific file.
    if (ptrF == NULL)
    {
        printf("file can't be opened. \n");
    } 
    char chunk_file[CHUNK_SIZE] = {0};
    int size_file = 0;
    int len = 0;
    // Fill in the destination address
    socklen_t addrlen;
    addrlen = sizeof(server_addr);
    socklen_t addrlen6;
    addrlen6 = sizeof(server_addr6);
    while (size_file < SIZE)
    {
        fread(chunk_file, 1, CHUNK_SIZE, ptrF);
	
        // send the data 
        if (flage == TCP4)
        {
            len = send(sockfd, chunk_file, BUF_SIZE, 0);
        }
        else if (flage == UDP4)
        {  
            len = sendto(sockfd, chunk_file, BUF_SIZE, 0, (struct sockaddr *)&server_addr, addrlen);
      	    sleep(0.01);
      	    gap++; 
        }
        else if (flage == TCP6)
        {
            len = sendto(sockfd, chunk_file, BUF_SIZE, 0, (struct sockaddr *)&server_addr6, addrlen6); 
        }
        else if(flage == UDP6)
        {
            len = sendto(sockfd, chunk_file, BUF_SIZE, 0, (struct sockaddr *)&server_addr6, addrlen6);
      	    sleep(0.01);
      	    gap++;
        }
        if (len < 0)
        {
            perror("sendto");
            return;
        }
        size_file += len;
        len = 0;
       
    }
    if (flage == UDP4)
    {
        sleep(0.1);
        sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&server_addr, addrlen);
    }
    if (flage == UDP6)
    {
        sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&server_addr6, addrlen6);
    }
    
    
}


int ipv4 = 0;
int ipv6 = 0;
int uds = 0;
int tcp = 0;
int udp = 0;
int stream = 0;
int dgram = 0;
void explor_command(int argc, char* argv[])
{
        for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-c") == 0) {
            is_client = 1;
            ip = argv[i+1];
            ip_s = argv[i+1];
            port = atoi(argv[i+2]);
        }
        if (strcmp(argv[i], "-s") == 0) {
            is_server = 1;
            port = atoi(argv[i+1]);
        }
        
        if (strcmp(argv[i], "ipv4") == 0) 
        {
            ipv4 = 1;
        }
        if ((strcmp(argv[i], "tcp") == 0))
            {
                tcp = 1;
            }
        if ((strcmp(argv[i], "udp") == 0)) 
            {
                udp = 1;
            } 
        
        if (strcmp(argv[i], "ipv6") == 0) 
        {
             ipv6 = 1;   
        }
        if (strcmp(argv[i], "uds") == 0) 
        {
 	    uds = 1;
        }            
        if ((strcmp(argv[i], "dgram") == 0))
	    {
		dgram = 1;
		
	    }
	if ((strcmp(argv[i], "stream") == 0)) 
	    {
		stream = 1;
		
	    }
	
	if (ipv4 && tcp)
	{
	    flage = 1;
	}
	
	if (ipv4 && udp)
	{
	    flage = 3;
	} 
	
	if (ipv6 && tcp)
	{
	    flage = 2; 
	}
	
	if (ipv6 && udp)
	{
	    flage = 4;
	}
	
	if (uds && dgram)
	{
	    flage = 5; 
	}  
	if (uds && stream)
	{
	    flage = 6;
	} 
        if (strcmp(argv[i], "mmap") == 0) 
        {
            flage = 7;
        } 
        if (strcmp(argv[i], "pipe") == 0) 
        {
            flage = 8;

        }
        if (strcmp(argv[i], "-p") == 0)
        {
            test_performance = 1;
        }
        if (strcmp(argv[i], "-q") == 0)
        {
            q = 1;
        }    
    }
}

void write_data(int fd, FILE *file, int socket_type) 
{
    char buf[1024];
    ssize_t len;
    if (socket_type == SOCK_STREAM) 
    {
        // For stream sockets, use send() and recv()
        while ((len = fread(buf, 1, 1024, file)) > 0) 
        {
            send(fd, buf, len, 0);
        }
    } 
    else 
    {
        while ((len = fread(buf, 1, 1024, file)) > 0) 
        {
            sendto(fd, buf, len, 0, NULL, 0);
        }
        sendto(fd, buf, len, 0, NULL, 0);
    }
}

void uds_client(int is_stream)
{
    sleep(1);
    int socket_type;
    if (is_stream) 
    {
        socket_type = SOCK_STREAM;
    } 
    else 
    {
        socket_type = SOCK_DGRAM;
    } 

    int sfd;
    struct sockaddr_un addr;

    // Create socket
    if ((sfd = socket(AF_UNIX, socket_type, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    // Set up address structure
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/uds_socket", sizeof(addr.sun_path) - 1);

    // Connect to the server
    if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        exit(1);
    }

    // Open the input file
    FILE *input = fopen("FileToSend.txt", "rb");
    if (!input) 
    {
    perror("fopen");
    exit(1);
    } 
    // Read and write data
    write_data(sfd, input, socket_type);

    fclose(input);
    close(sfd);

    if(!q) {printf("File sent successfully.\n");}
}

void server_receive_file(int cfd, int socket_type, const char *output_file) 
{
    char buf[1024];
    ssize_t len;

    // Open the output file
    FILE *output = fopen(output_file, "wb");
    if (!output) {
        perror("fopen");
        exit(1);
    }
    gettimeofday(&start, NULL);
    if (socket_type == SOCK_STREAM) 
    {
        // For stream sockets, use recv()
        while ((len = recv(cfd, buf, 1024, 0)) > 0) 
        {
            fwrite(buf, 1, len, output);
        }
    } 
    else 
    {
        // For datagram sockets, use recvfrom()
        struct sockaddr_un addr;
        socklen_t addr_len = sizeof(addr);

        while ((len = recvfrom(cfd, buf, 1024, 0, (struct sockaddr *)&addr, &addr_len)) > 0) 
        {
            fwrite(buf, 1, len, output);
        }
    }
    gettimeofday(&end, NULL);
    time2 = (end.tv_sec - start.tv_sec) + (end.tv_usec - 
    start.tv_usec) / 1000000.0;

    fclose(output);
}

void uds_server(int is_srtream)
{

    int socket_type;
    if (is_srtream) 
    {
        socket_type = SOCK_STREAM;
    } 
    else 
    {
        socket_type = SOCK_DGRAM;
    }
    
    int sfd, cfd;
    struct sockaddr_un addr;


    // Create socket
    if ((sfd = socket(AF_UNIX, socket_type, 0)) == -1) 
    {
        perror("socket");
        exit(1);
    }
    

    // Remove any existing socket file
    unlink("/tmp/uds_socket");

    // Set up address structure
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/uds_socket", sizeof(addr.sun_path) - 1);

    // Bind socket to address
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) 
    {
        perror("bind");
        exit(1);
    }

    if (socket_type == SOCK_STREAM) 
    {
        // Listen for incoming connections
        if (listen(sfd, 1) == -1) 
        {
            perror("listen");
            exit(1);
        }

        // Accept a connection
        if ((cfd = accept(sfd, NULL, NULL)) == -1) 
        {
            perror("accept");
            exit(1);
        }
    } 
    else 
    {
        cfd = sfd;
    }

    server_receive_file(cfd, socket_type, "FileToRecv.txt"); 
    
    close(cfd);
    close(sfd);

    
}

void pipe_send()
{
    int fd;
    char* fifo_name = "myfifo";
    
    // Remove old FIFO
    unlink(fifo_name);

    // Create the FIFO
    if (mkfifo(fifo_name, 0666) == -1) 
    {
        perror("mkfifo");
        exit(1);
    }
    
    // Open the FIFO for writing
    if ((fd = open(fifo_name, O_WRONLY)) == -1) 
    {
        perror("open");
        exit(1);
    }

    // Open the file to send
    FILE * fileToSend = fopen("FileToSend.txt", "r");
    if (fileToSend == NULL) 
    {
        perror("fopen");
        exit(1);
    }
    
    char buffer[BUFSIZ];
    size_t bytesRead;

    // Read the file and write its contents to the FIFO
    while ((bytesRead = fread(buffer, 1, BUFSIZ, fileToSend)) > 0) 
    {
        write(fd, buffer, bytesRead);
    }

    // Close the file and the FIFO
    fclose(fileToSend);
    close(fd);
    // Remove the FIFO
    unlink(fifo_name);
    

}

void pipe_receive()
{
    sleep(1);

    int fd;
    char* fifo_name = "myfifo";

    // Open the FIFO for reading
    if ((fd = open(fifo_name, O_RDONLY)) == -1) {
        perror("open");
        exit(1);
    }

    FILE *fp = fopen("FileToRecv.txt", "wb");
    if (fp == NULL) 
    {
        perror("fopen");
        exit(1);
    }

    char buffer[BUFSIZ];
    ssize_t bytesRead;
    gettimeofday(&start, NULL);
    // Read the contents of the FIFO and print them to stdout
    while ((bytesRead = read(fd, buffer, BUFSIZ)) > 0) 
    {
        fwrite(buffer, 1, bytesRead, fp);
    }
    
    gettimeofday(&end, NULL);
    time3 = (end.tv_sec - start.tv_sec) + (end.tv_usec - 
    start.tv_usec) / 1000000.0;
    // Close the FIFO
    close(fd);

    // Close the file.
    fclose(fp);

    // Remove the FIFO
    unlink(fifo_name);

}

void mmap_send()
{
    char* smn = "/mmap_file_sharing";
    int fd = open(FILE_TO_SEND, O_RDONLY);
    if (fd < 0) 
    {
        perror("File open error");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) 
    {
        perror("File stat error");
        close(fd);
        return;
    }

    size_t size = st.st_size;

    int shm_fd = shm_open(smn, O_CREAT | O_RDWR, 0666);
    if (shm_fd < 0) 
    {
        perror("Shared memory creation error");
        close(fd);
        return;
    }

    ftruncate(shm_fd, size); // resize the shared mamory to the file size.

    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (addr == MAP_FAILED) 
    {
        perror("Memory mapping error");
        close(fd);
        shm_unlink(smn);
        return;
    }

    read(fd, addr, size);

    close(fd);

}

void mmap_receive()
{
    sleep(1);

    char* smn = "/mmap_file_sharing";
    char* rcf = "FileToRecv.txt";
    int shm_fd = shm_open(smn, O_RDONLY, 0666);
    if (shm_fd < 0) 
    {
        perror("Shared memory open error");
        return;
    }

    struct stat st;
    if (fstat(shm_fd, &st) < 0) 
    {
        perror("Shared memory stat error");
        close(shm_fd);
        return;
    }
    gettimeofday(&start, NULL);
    size_t size = st.st_size;

    void *addr = mmap(NULL, size, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (addr == MAP_FAILED) 
    {
        perror("Memory mapping error");
        close(shm_fd);
        return;
    }

    int fd = open(rcf, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) 
    {
        perror("File open error");
        munmap(addr, size);
        close(shm_fd);
        return;
    }

    write(fd, addr, size);

    munmap(addr, size);
    
    gettimeofday(&end, NULL);
    time4 = (end.tv_sec - start.tv_sec) + (end.tv_usec - 
    start.tv_usec) / 1000000.0;
    
    close(fd);
    close(shm_fd);

}


int main(int argc, char* argv[])
{    

    if (argc != 8) 
    {
        fprintf(stderr, "Communication protocol not specified.\n");
        print_usage();
        return -1;
    }

    explor_command(argc, argv);
    if (is_server && !q)
    {
        printf("Launching to server \n");
    }
    else if (is_client && !q)
        printf("Launching to client \n");
    
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return 1;
    }
    // Bind to local address and port if server, otherwise connect to 
    
    if (is_server)
    {
        call_server();
    }
    
    // If client
    if(is_client)
    {
        call_client();
    }
    
    
    if(!test_performance && flage == 0)
    {
    	start_chat();
    }
    
    if (flage == TCP4)
    {
        if (is_server){recv_data();
        printf("ipv4_tcp,%f \n" , time1);
        return 0;
        }
        if (is_client){send_data();if(!q) {printf("Send File\n");}}
        
    }
    if (flage == UDP4)
    {
        if (is_server){udp_ipv4_server(); recv_data();
        printf("ipv4_udp,%f \n" , (time1 - (0.01 * gap)));
        return 0;
        }
        if (is_client){udp_ipv4_client(); send_data();if(!q) {printf("Send File\n");}}
        
        
    }
    if (flage == TCP6 || flage == UDP6)
    {
        if (is_server){ipv6_server(); recv_data();
        if(flage == TCP6) {printf("ipv6_tcp,%f \n" , (time1));}
        else {printf("ipv6_udp,%f \n" , (time1 - (0.01 * gap)));}
        return 0;
        }
        if (is_client){ipv6_client(); send_data();if(!q){ printf("Send File\n");}}
        
    }
    if(flage == UDGRM)
    {
        if (is_server){uds_server(0);
        printf("dgram_uds,%f \n" , (time2));
        return 0;
        }
        if (is_client){uds_client(0);if(!q) {printf("Send File\n");}}
        
    }
    if(flage == UDSTRM)
    {
        if (is_server){uds_server(1);
        printf("stream_uds,%f \n" , (time2));
        }
        if (is_client){uds_client(1);if(!q) {printf("Send File\n");}}
        
        
    }
    if(flage == PIPE)
    {
        if (is_server){pipe_receive();
        printf("pipe,%f \n" , (time3));
        }
        if (is_client){pipe_send();if(!q) {printf("Send File\n");}}
        
        
    }
    if(flage == MMAP)
    {
        if (is_server){mmap_receive();
        printf("mmap,%f \n" , (time4));
        }
        if (is_client){mmap_send(); if(!q) {printf("Send File\n");}}
        
        
    }
    close(sockfd);
    return 0;

}
