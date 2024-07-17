#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <netdb.h>   

#define BUF_SIZE 512

// Function prototypes
void create_query(unsigned char *buf, int *query_len, const char *domain_name);
void parse_response(unsigned char *buf, int response_len);
int parse_unsigned_int(const unsigned char *buf, int *index, int byte_length);
void parse_name(const unsigned char *buf, int *index, char *name);

// Function to create DNS query message
void create_query(unsigned char *buf, int *query_len, const char *domain_name) {

    // create DNS query message
    // Query header [RFC 4.1.1. Header section format]
    // 1 1 1 1 1 1
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | ID |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |QR| Opcode |AA|TC|RD|RA| Z | RCODE |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | QDCOUNT |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | ANCOUNT |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | NSCOUNT |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | ARCOUNT |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    unsigned short id = htons(0x1234); // ID
    unsigned short flags = htons(0x0100); // Standard query with recursion
    unsigned short qdcount = htons(1); // One question
    unsigned short ancount = htons(0);
    unsigned short nscount = htons(0);
    unsigned short arcount = htons(0);

    memcpy(buf, &id, 2);
    memcpy(buf + 2, &flags, 2);
    memcpy(buf + 4, &qdcount, 2);
    memcpy(buf + 6, &ancount, 2);
    memcpy(buf + 8, &nscount, 2);
    memcpy(buf + 10, &arcount, 2);

    // Question section [RFC 4.1.2. Question section format]
    // 1 1 1 1 1 1
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | |
    // / QNAME /
    // / /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | QTYPE |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | QCLASS |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    *query_len = 12;

    // Question section
    const char *label = domain_name;
    while (*label) {
        const char *next_label = strchr(label, '.');
        int label_len = next_label ? next_label - label : strlen(label);
        buf[(*query_len)++] = label_len;
        memcpy(buf + *query_len, label, label_len);
        *query_len += label_len;
        if (!next_label) break;
        label = next_label + 1;
    }
    buf[(*query_len)++] = 0; // End of QNAME

    unsigned short qtype = htons(1); // A record
    unsigned short qclass = htons(1); // IN class
    memcpy(buf + *query_len, &qtype, 2);
    *query_len += 2;
    memcpy(buf + *query_len, &qclass, 2);
    *query_len += 2;
}

// Function to parse unsigned integer from response
int parse_unsigned_int(const unsigned char *buf, int *index, int byte_length) {
    int num = 0;
    for (int i = 0; i < byte_length; i++) {
        num = (num << 8) | buf[(*index)++];
    }
    return num;
}

// Function to parse name from response
void parse_name(const unsigned char *buf, int *index, char *name) {
    int pos = 0;
    int jumped = 0;
    int offset = *index;

    while (buf[*index] != 0) {
        if (buf[*index] >= 192) { // 192 = 11000000 in binary, indicates a pointer
            if (!jumped) offset = *index + 2;
            jumped = 1;
            *index = (buf[*index] - 192) * 256 + buf[*index + 1];
        } else {
            name[pos++] = buf[*index];
            (*index)++;
        }
    }
    name[pos] = '\0';
    if (!jumped) (*index)++;
    else *index = offset;
}

void parse_response(unsigned char *buf, int response_len) {
    printf("----- parse response -----\n");

    // dns message format [RFC 4.1. Format]
    // This example will only parse header and question sections.
    //
    // +---------------------+
    // | Header |
    // +---------------------+
    // | Question | the question for the name server
    // +---------------------+
    // | Answer | RRs answering the question
    // +---------------------+
    // | Authority | RRs pointing toward an authority
    // +---------------------+
    // | Additional | RRs holding additional information
    // +---------------------+

    // current byte index
    int index = 0;

    printf("Header section [RFC 4.1.1. Header section format]\n");

    unsigned short id = parse_unsigned_int(buf, &index, 2);
    unsigned short flags = parse_unsigned_int(buf, &index, 2);
    unsigned short qdcount = parse_unsigned_int(buf, &index, 2);
    unsigned short ancount = parse_unsigned_int(buf, &index, 2);
    unsigned short nscount = parse_unsigned_int(buf, &index, 2);
    unsigned short arcount = parse_unsigned_int(buf, &index, 2);

    printf("ID: %u\n", id);
    printf("Flags: %u\n", flags);
    printf("QDCOUNT: %u\n", qdcount);
    printf("ANCOUNT: %u\n", ancount);
    printf("NSCOUNT: %u\n", nscount);
    printf("ARCOUNT: %u\n", arcount);

    // Question section [RFC 4.1.2. Question section format]
    // 1 1 1 1 1 1
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                                               |
    // /                      QNAME                    /
    // /                                               /
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      QTYPE                    |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                      QCLASS                   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    printf("Question section [RFC 4.1.2. Question section format]\n");
    
    printf("QNAME: ");
    while (buf[index] != 0) {
        int len = buf[index++];
        for (int i = 0; i < len; ++i) {
            printf("%c", buf[index++]);
            if (i+1 == len && buf[index] != 0) {
                printf(".");
            }
        }
    }
    printf("\n");

    unsigned short qtype = parse_unsigned_int(buf, &index, 2);
    unsigned short qclass = parse_unsigned_int(buf, &index, 2);

    printf("QTYPE: %u\n", qtype);
    printf("QCLASS: %u\n", qclass);

}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s domain-name root-dns-ip\n", argv[0]);
        return 1;
    }

    char* domain_name = argv[1];
    char* root_dns_ip = argv[2];
    fprintf(stderr, "Domain Name: %s\nRoot DNS IP: %s\n", domain_name, root_dns_ip);

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    server_addr.sin_addr.s_addr = inet_addr(root_dns_ip);

    // Create DNS query
    unsigned char buf[BUF_SIZE];
    int query_len;
    create_query(buf, &query_len, domain_name);

    // Send DNS query
    if (sendto(sock, buf, query_len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    // Receive DNS response
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    int response_len = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&from_addr, &from_len);
    if (response_len < 0) {
        perror("recvfrom");
        close(sock);
        return 1;
    }

    // Parse DNS response
    parse_response(buf, response_len);

    close(sock);
    return 0;
}
