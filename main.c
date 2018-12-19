#include "httpsheader.h"

U32 clnt_cnt = 0;
U32 clnt_socks[MAX_CLNT];

U32 main(S32 argc, U8 * argv[])
{
    S32 serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    S32 clnt_adr_size;
    pthread_t t_id;

    if(argc!=2){
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    pthread_mutex_init(&mutx, NULL);
    serv_sock=socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family=AF_INET;
    serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if(bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1) printError("bind() error");
    if(listen(serv_sock, 20) == -1) printError("listen() error");

    clnt_adr_size=sizeof(clnt_adr);
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    while(1)
    {
        clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_size);
        printf("Connection Request : %s:%d\n", inet_ntoa(clnt_adr.sin_addr), ntohs(clnt_adr.sin_port));


        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt++] = clnt_sock;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
        pthread_detach(t_id);

    }

    close(serv_sock);
    pthread_mutex_destroy(&mutx);

    return 0;
}

void * handle_clnt(void * sock){
    U32 clnt_sock = *(U32*)sock;
    printf("clnt_sock : %d\n", clnt_sock);
    U32 str_len = 0, i;
    U8 msg[BUFSIZE], hostname[HOSTNAMELEN];

    while((str_len = read(clnt_sock, msg, sizeof(msg))) !=0) {
        U32 hostlen = isHttps(msg, hostname);
        if(hostlen) {
            send_msg(msg, str_len, clnt_sock, hostname, hostlen);
            memset(msg, 0, BUFSIZE);
            memset(hostname, 0, HOSTNAMELEN);
        }
    }

    pthread_mutex_lock(&mutx);

   for(i = 0; i<clnt_cnt; i++){
        if(clnt_sock == clnt_socks[i]){
            while(i++<clnt_cnt - 1) clnt_socks[i] = clnt_socks[i+1];
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);
    close(clnt_sock);
    return NULL;

}
void send_msg(U8 * msg, U32 len, U32 clnt_sock, U8 * hostname, U32 hostlen){
    S32 sockets[2];
    U8 connection[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    struct sockaddr_in serv_addr;
    pthread_t rcv_thread;
    struct hostent * tmp = gethostbyname(hostname);
    S32 acc;
    SSL_CTX *clnt_ctx, *proxy_ctx;
    SSL *clnt_ssl, * proxy_ssl;
    SSL_METHOD * clnt_meth, * proxy_meth;
    arg argstr;

    clnt_meth = TLS_client_method();
    clnt_ctx = SSL_CTX_new(clnt_meth);
    proxy_meth = TLS_server_method();
    proxy_ctx = SSL_CTX_new(proxy_meth);

	printf("hostname : %s\n", hostname);
    configure_clnt_context(clnt_ctx);
    configure_proxy_context(proxy_ctx, hostname, hostlen);

    printf("connection : %s\n", connection);
    sockets[1] = clnt_sock;
    sockets[0] = socket(PF_INET, SOCK_STREAM, 0);
    strcpy(hostname, inet_ntoa(*(struct in_addr*)tmp->h_addr_list[0]));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(hostname);
    serv_addr.sin_port=htons(443);

    write(sockets[1], connection, strlen(connection));

    proxy_ssl = SSL_new(proxy_ctx);
    acc = SSL_accept(proxy_ssl);
    printf("SSL connection using %s\n", SSL_get_cipher(proxy_ssl));
    printf("accept : %d\n", acc);

    clnt_ssl = SSL_new(clnt_ctx);
    SSL_set_fd(clnt_ssl, sockets[0]);


    if(connect(sockets[0], (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)printError("connect() error");

    if(SSL_connect(clnt_ssl) ==0){
        printf("connection failed\n");
    }

    argstr.clnt_ssl = clnt_ssl;
    argstr.proxy_ssl = proxy_ssl;
    pthread_create(&rcv_thread, NULL, rcvMsg, (void*)&argstr);

    SSL_write(clnt_ssl, msg, len);


    close(clnt_sock);

    SSL_free(proxy_ssl);
    SSL_CTX_free(proxy_ctx);
}


void rcvMsg(void* argstr){
    S8 fromSrvMsg[BUFSIZE];
    S32 str_len;

    while((str_len = SSL_read(((arg*)argstr)->clnt_ssl, fromSrvMsg, sizeof(BUFSIZE))) > 0){
        memset(fromSrvMsg, 0, BUFSIZE);
        SSL_write(((arg*)argstr)->proxy_ssl, fromSrvMsg, str_len);
    }


}
