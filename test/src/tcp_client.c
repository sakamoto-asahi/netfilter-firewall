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
    if (argc != 3) {
        fprintf(stderr, "サーバのIPアドレスとポート番号を指定してください。\n");
        return 1;
    }

    char server_ip[INET_ADDRSTRLEN];
    if (is_valid_ip(argv[1]) == false) {
        fprintf(stderr, "指定されたIPアドレスの形式が正しくありません。\n");
        return 1;
    }
    snprintf(server_ip, sizeof(server_ip), "%s", argv[1]);
    int port = parse_port(argv[2]);
    if (port == -1) {
        fprintf(stderr, "ポート番号は0~65535の数字を指定してください。\n");
        return 1;
    }

    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(port);

    while (true) {
        printf("Enterでサーバへ接続>");
        getchar();

        char timestamp[64];
        int ret = connect(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
        get_now_time(timestamp, sizeof(timestamp));
        if (ret == -1) {
            fprintf(stderr, "[%s] サーバへの接続に失敗しました。\n\n", timestamp);
            continue;
        }
        printf("[%s] サーバと接続しました。\n\n", timestamp);

        while (true) {
            printf("Enterでサーバにパケットを送信>");
            getchar();

            char buf[16] = "\n";
            int send_size = send(client_sock, buf, strlen(buf), 0);
            get_now_time(timestamp, sizeof(timestamp));
            if (send_size == -1) {
                fprintf(stderr, "[%s] パケットの送信に失敗しました。\n\n", timestamp);
                continue;
            }
            printf("[%s] サーバにパケットを送信しました。\n", timestamp);

            int recv_size = recv(client_sock, buf, sizeof(buf), 0);
            get_now_time(timestamp, sizeof(timestamp));
            if (recv_size == -1) {
                fprintf(stderr, "[%s] パケットの受信に失敗しました。\n\n", timestamp);
                continue;
            } else if (recv_size == 0) {
                printf("[%s] サーバが切断しました。\n\n", timestamp);
                break;
            }
            printf("[%s] サーバから応答がありました。\n\n", timestamp);
        }
    }

    close(client_sock);
    return 0;
}