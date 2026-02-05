#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
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

    int client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(port);

    while (true) {
        char timestamp[64];
        printf("Enterでパケットを送信>");
        getchar();

        int send_size = sendto(client_sock, NULL, 0, 0, (struct sockaddr *)&server_addr, server_len);
        if (send_size == -1) {
            fprintf(stderr, "パケットの送信に失敗しました。\n\n");
            continue;
        }
        get_now_time(timestamp, sizeof(timestamp));
        printf("[%s] サーバにパケットを送信しました。\n", timestamp);

        int recv_size = recvfrom(client_sock, NULL, 0, 0, NULL, NULL);
        if (recv_size == -1) {
            fprintf(stderr, "パケットの受信に失敗しました。\n\n");
            continue;
        }
        get_now_time(timestamp, sizeof(timestamp));
        printf("[%s] サーバから応答がありました。\n\n", timestamp);
    }

    close(client_sock);
    return 0;
}