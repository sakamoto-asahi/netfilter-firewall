#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

int parse_port(const char *port_str)
{
    if (port_str == NULL) {
        return -1;
    }

    char *endptr;
    long port_val = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_val < 0 || port_val > 65535) {
        return -1;
    }

    return (int)port_val;
}

bool is_valid_ip(const char *ip_str)
{
    if (ip_str == NULL) {
        return false;
    }

    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_str, &(sa.sin_addr));

    if (result == 1) {
        return true;
    } else {
        return false;
    }
}

bool get_my_ip(char *ip_out, size_t ip_len)
{
    if (ip_out == NULL) {
        return false;
    }

    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return false;
    }

    struct ifaddrs *ifa = ifaddr;
    while (ifa != NULL) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        // ループバック以外のIPv4アドレスを探す
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
            struct sockaddr_in *my_addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &my_addr->sin_addr, ip_out, ip_len);
        }

        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddr);
    return true;
}

void get_now_time(char *time_str, size_t time_len)
{
    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    strftime(time_str, time_len, "%H:%M:%S", local);
}