#include <liburing.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define PORT 9877
#define LISTENQ 1024
#define MAX_LEN 1024

#define SERVER_STRING "Server: zerohttpd/0.1\r\n"
#define DEFAULT_SERVER_PORT 8000
#define QUEUE_DEPTH 256
#define READ_SZ 8192

#define EVENT_TYPE_ACCEPT 0
#define EVENT_TYPE_READ 1
#define EVENT_TYPE_WRITE 2

struct request {
    int event_type;
    int iovec_count;
    int client_socket;
    struct iovec iov[];
};

struct io_uring ring;
int get_socket() {
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("wrong getting socket");
        return 1;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        return 1;
    }
    if (listen(sockfd, LISTENQ) < 0) {
        perror("listen error");
        return 1;
    }
    return sockfd;
}

int add_accept_request(int server_socket, struct sockaddr_in *client_addr,
                       socklen_t *client_addr_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, server_socket, (struct sockaddr *)client_addr,
                         client_addr_len, 0);
    struct request *req = malloc(sizeof(*req));
    req->event_type = EVENT_TYPE_ACCEPT;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);

    return 0;
}

int add_read_request(int client_socket) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct request *req = malloc(sizeof(*req) + sizeof(struct iovec));
    req->iov[0].iov_base = malloc(READ_SZ);
    req->iov[0].iov_len = READ_SZ;
    req->event_type = EVENT_TYPE_READ;
    req->client_socket = client_socket;
    memset(req->iov[0].iov_base, 0, READ_SZ);
    /* Linux kernel 5.5 has support for readv, but not for recv() or read() */
    io_uring_prep_readv(sqe, client_socket, &req->iov[0], 1, 0);
    /* sqe->flags |= IOSQE_FIXED_FILE; */
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_write_request(struct request *req) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_WRITE;
    io_uring_prep_writev(sqe, req->client_socket, req->iov, req->iovec_count,
                         0);
    /* sqe->flags |= IOSQE_FIXED_FILE; */
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

void handle_client_request(struct request *rcv_req) {
    struct request *echo_req =
        (struct request *)malloc(sizeof(*echo_req) + sizeof(struct iovec));
    char str[MAX_LEN];
    strcpy(str, rcv_req->iov[0].iov_base);
    size_t len = strlen(str);
    printf("%s", str);
    echo_req->iovec_count = 1;
    echo_req->client_socket = rcv_req->client_socket;
    echo_req->iov[0].iov_base = malloc(len);
    echo_req->iov[0].iov_len = len;
    memcpy(echo_req->iov[0].iov_base, str, len);
    add_read_request(rcv_req->client_socket);
    add_write_request(echo_req);
}

void server_loop(int server_socket) {
    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    client_addr_len = sizeof(client_addr);

    add_accept_request(server_socket, &client_addr, &client_addr_len);

    while (1) {
        int ret = io_uring_wait_cqe(&ring, &cqe);
        struct request *req = (struct request *)cqe->user_data;
        if (ret < 0) {
            perror("io_uring_wait failed");
            exit(1);
        }
        if (cqe->res < 0) {
            fprintf(stderr, "Async request failed: %s for event: %d\n",
                    strerror(-cqe->res), req->event_type);
            exit(1);
        }

        switch (req->event_type) {
        case EVENT_TYPE_ACCEPT:
            add_accept_request(server_socket, &client_addr, &client_addr_len);
            add_read_request(cqe->res);
            free(req);
            break;
        case EVENT_TYPE_READ:
            if (!cqe->res) {
                fprintf(stderr, "Empty request!\n");
                break;
            }
            handle_client_request(req);
            free(req->iov[0].iov_base);
            free(req);
            break;
        case EVENT_TYPE_WRITE:
            for (int i = 0; i < req->iovec_count; i++) {
                free(req->iov[i].iov_base);
            }
            free(req);
            break;
        }
        io_uring_cqe_seen(&ring, cqe);
    }
}

void sigint_handler(int signo) {
    printf("Receive Interrupt");
    io_uring_queue_exit(&ring);
    exit(0);
}
void exit_callback() { io_uring_queue_exit(&ring); }

int main() {
    int sockfd;

    // get socket ready;
    sockfd = get_socket();

    // register sigint;
    signal(SIGINT, sigint_handler);

    // init io_uring
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    params.flags |= IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 2000;
    io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);
    /* io_uring_queue_init(QUEUE_DEPTH, &ring, 0); */

    atexit(exit_callback);
    // enter server loop;
    server_loop(sockfd);
}
