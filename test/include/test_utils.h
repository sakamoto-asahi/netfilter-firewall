#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdbool.h>

int parse_port(const char *port_str);
bool is_valid_ip(const char *ip_str);
bool get_my_ip(char *ip_out, size_t ip_len);
void get_now_time(char *time_str, size_t time_len);

#endif