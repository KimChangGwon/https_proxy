#ifndef SRV_HEADER_H
#define SRV_HEADER_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSIZE 100000
#define MAX_CLNT 100
#define HOSTNAMELEN 100

typedef int64_t S64;
typedef int32_t S32;
typedef int16_t S16;
typedef int8_t S8;

typedef uint64_t U64;
typedef uint32_t U32;
typedef uint16_t U16;
typedef uint8_t U8;

typedef struct arg{
    SSL * clnt_ssl;
    SSL * proxy_ssl;
} arg;

void * handle_clnt(void * arg);
void send_msg(U8 * msg, U32 len, U32 clnt_sock, U8 * hostname, U32 hostlen);
void rcvMsg(void * sock);
U32 isHttps(unsigned char * msg, U8 * hostname);
void configure_proxy_context(SSL_CTX *ctx, char * host, int hostLen);
void configure_clnt_context(SSL_CTX *ctx);

pthread_mutex_t mutx;


U32 isHttps(unsigned char * msg, U8 * hostname){
    U32 hostLen = 0;
    int i;
    char connect[] = "CONNECT ";
    if(!strncmp(msg, connect, strlen(connect))){
        U32 hostIdx = 8;
        while(*(msg+hostIdx) != ':'){
           hostname[hostLen++] = *(msg+hostIdx);
           hostIdx++;
        }
        hostname[hostLen] = '\0';
    }


    return hostLen;
}

void configure_clnt_context(SSL_CTX *ctx)
{
    char certPath[100] = "/home/yg/Desktop/cert-master/yg.crt";
    char keyPath[100] = "/home/yg/Desktop/cert-master/yg.pem";

    if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Client Private key does not match the certificate public key\n");
        exit(5);
    }
}

void configure_proxy_context(SSL_CTX *ctx, char * host, int hostLen)
{
    char certPath[100] = "/home/yg/Desktop/cert-master/";
    char keyPath[100] = "/home/yg/Desktop/cert-master/";

    strncat(certPath, host, hostLen);
    strncat(certPath, ".crt", 4);

    strncat(keyPath, host, hostLen);
    strncat(keyPath, ".pem", 4);

    if(access(certPath, 0)){
        char command[100] = "cd /home/yg/Desktop/cert-master/ && ./_make_site.sh ";
	printf("host : %s\n", host);
	strncat(command, host, hostLen);
        printf("command : %s\n", command);
        system(command);
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if(!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Proxy Private key does not match the certificate public keyn");
        exit(5);
    }
}

void printError(U8 * errstr){
    fprintf(stderr, "%s\n", errstr);
    exit(1);
}

#endif // SRV_HEADER_H

