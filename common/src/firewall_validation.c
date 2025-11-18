#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include "firewall_config.h"
#include "firewall_parser.h"
#include "firewall_validation.h"

bool is_valid_ip(const char *ip_str)
{
    if (ip_str == NULL) {
        return false;
    }

    if (strcmp(ip_str, "ANY") == 0) {
        return true;
    }

    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_str, &(sa.sin_addr));

    if (result == 1) {
        return true;
    } else {
        return false;
    }
}

bool is_valid_port(const char *port_str)
{
    if (port_str == NULL) {
        return false;
    }

    if (strcmp(port_str, "ANY") == 0) {
        return true;
    }

    char *endptr;
    long port_val = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port_val < 0 || port_val > 65535) {
        return false;
    }

    return true;
}

RuleValidationResult is_valid_rule_string(const char *rule_str)
{
    if (rule_str == NULL) {
        return RULE_STR_ERR_INTERNAL;
    }

    // strtok_rは元の文字列を破壊するので、コピーを使う
    char copy[RULE_MAX_LEN];
    snprintf(copy, sizeof(copy), "%s", rule_str);
    copy[strcspn(copy, "\r\n")] = '\0';

    // トークンを順次処理し、値を検証する
    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_CHAIN;
    }
    if (parse_chain_string(token) == CHAIN_UNSPECIFIED) {
        return RULE_STR_INVALID_CHAIN;
    }

    char protocol[PROTOCOL_MAX_LEN];
    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_PROTOCOL;
    }
    if (parse_protocol_string(token) == PROTO_UNSPECIFIED) {
        return RULE_STR_INVALID_PROTOCOL;
    }
    snprintf(protocol, sizeof(protocol), "%s", token);

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_SRC_IP;
    }
    if (is_valid_ip(token) == false) {
        return RULE_STR_INVALID_SRC_IP;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_SRC_PORT;
    }
    if (is_valid_port(token) == false) {
        return RULE_STR_INVALID_SRC_PORT;
    }
    if (strcmp(protocol, "ICMP") == 0 && strcmp(token, "ANY") != 0) {
        return RULE_STR_ERR_ICMP_PORT;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_DST_IP;
    }
    if (is_valid_ip(token) == false) {
        return RULE_STR_INVALID_DST_IP;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_DST_PORT;
    }
    if (is_valid_port(token) == false) {
        return RULE_STR_INVALID_DST_PORT;
    }
    if (strcmp(protocol, "ICMP") == 0 && strcmp(token, "ANY") != 0) {
        return RULE_STR_ERR_ICMP_PORT;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_ACTION;
    }
    if (parse_action_string(token) == ACTION_UNSPECIFIED) {
        return RULE_STR_INVALID_ACTION;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_LOG;
    }
    if (parse_log_string(token) == LOG_UNSPECIFIED) {
        return RULE_STR_INVALID_LOG;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        return RULE_STR_INVALID_STATE;
    }
    if (parse_state_string(token) == RULE_UNSPECIFIED) {
        return RULE_STR_INVALID_STATE;
    }

    return RULE_STR_VALID;
}

FileValidationResult is_valid_rule_file(FILE *fp)
{
    if (fp == NULL) {
        errno = EINVAL;
        return FILE_INVALID;
    }

    bool exists = false;
    char line[RULE_MAX_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (is_valid_rule_string(line) != RULE_STR_VALID) {
            fseek(fp, 0, SEEK_SET);
            return FILE_INVALID;
        }
        exists = true;
    }
    fseek(fp, 0, SEEK_SET);

    if (exists == false) {
        return FILE_NO_CONTENT;
    }

    return FILE_VALID;
}