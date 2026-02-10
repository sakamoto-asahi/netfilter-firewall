#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "test_utils.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "待ち受けるポート番号を指定してください。\n");
        return 1;
    }

    char server_ip[INET_ADDRSTRLEN];
    if (get_my_ip(server_ip, sizeof(server_ip)) == false) {
        fprintf(stderr, "IPアドレスの取得に失敗しました。\n");
        return 1;
    }
    int port = parse_port(argv[1]);
    if (port == -1) {
        fprintf(stderr, "ポート番号は0~65535の数字を指定してください。\n");
        return 1;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 1) == -1) {
        perror("listen");
        close(server_sock);
        return 1;
    }

    while (true) {
        printf("クライアントの接続を待っています...(IP: %s, PORT: %d)\n", server_ip, port);

        char timestamp[64];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        get_now_time(timestamp, sizeof(timestamp));
        if (client_sock == -1) {
            fprintf(stderr, "[%s] クライアントとの接続に失敗しました。\n\n", timestamp);
            continue;
        }
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[%s] %s と接続しました。\n\n", timestamp, client_ip);

        while (true) {
            printf("%s からのパケットを待っています...\n", client_ip);

            char buf[16];
            int recv_size = recv(client_sock, buf, sizeof(buf), 0);
            get_now_time(timestamp, sizeof(timestamp));
            if (recv_size == -1) {
                fprintf(stderr, "[%s] パケットの受信に失敗しました。\n\n", timestamp);
                continue;
            } else if (recv_size == 0) {
                printf("[%s] %s が切断しました。\n\n", timestamp, client_ip);
                close(client_sock);
                break;
            }
            printf("[%s] %s からパケットを受信しました。\n", timestamp, client_ip);

            int send_size = send(client_sock, buf, strlen(buf), 0);
            get_now_time(timestamp, sizeof(timestamp));
            if (send_size == -1) {
                fprintf(stderr, "[%s] パケットの送信に失敗しました。\n\n", timestamp);
                continue;
            }
            printf("[%s] %s にパケットを返しました。\n\n", timestamp, client_ip);
        }
    }

    close(server_sock);
    return 0;
}