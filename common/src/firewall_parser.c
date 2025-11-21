#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "firewall_config.h"
#include "firewall_validation.h"


ProtocolType get_protocol_from_number(uint8_t proto_num)
{
    switch (proto_num) {
        case 1:
            return PROTO_ICMP;
            break; // NOT REACHED
        case 6:
            return PROTO_TCP;
            break; // NOT REACHED
        case 17:
            return PROTO_UDP;
            break; // NOT REACHED
        default:
            return PROTO_UNSPECIFIED;
            break; // NOT REACHED
    }
}

bool get_packet_ports(const unsigned char *packet, int *src_port, int *dst_port)
{
    if (packet == NULL || (src_port == NULL && dst_port == NULL)) {
        errno = EINVAL;
        return false;
    }

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    int protocol = ip_hdr->protocol;

    switch (protocol) {
        case IPPROTO_TCP:
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_hdr_len);
            if (src_port != NULL) {
                *src_port = ntohs(tcp_hdr->th_sport);
            }
            if (dst_port != NULL) {
                *dst_port = ntohs(tcp_hdr->th_dport);
            }
            break;
        case IPPROTO_UDP:
            struct udphdr *udp_hdr = (struct udphdr *)(packet + ip_hdr_len);
            if (src_port != NULL) {
                *src_port = ntohs(udp_hdr->uh_sport);
            }
            if (dst_port != NULL) {
                *dst_port = ntohs(udp_hdr->uh_dport);
            }
            break;
        default:
            // ポート番号が存在しないプロトコルのパケットには、-1（全て許可）を設定する
            if (src_port != NULL) {
                *src_port = -1;
            }
            if (dst_port != NULL) {
                *dst_port = -1;
            }
            break;
    }

    return true;
}

bool config_to_string(ConfigType config, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    switch (config) {
        case CONFIG_INPUT_POLICY:
            snprintf(str_out, str_len, "INPUT_POLICY");
            break;
        case CONFIG_OUTPUT_POLICY:
            snprintf(str_out, str_len, "OUTPUT_POLICY");
            break;
        case CONFIG_DEFAULT_LOGGING:
            snprintf(str_out, str_len, "DEFAULT_LOGGING");
            break;
        case CONFIG_LOGFILE_ROTATE:
            snprintf(str_out, str_len, "LOGFILE_ROTATE");
            break;
        case CONFIG_LOG_ROTATION_SIZE:
            snprintf(str_out, str_len, "LOG_ROTATION_SIZE_MB");
            break;
        case CONFIG_ICMP_TIMEOUT_SEC:
            snprintf(str_out, str_len, "ICMP_CONNECTION_TIMEOUT_SEC");
            break;
        case CONFIG_TCP_TIMEOUT_SEC:
            snprintf(str_out, str_len, "TCP_CONNECTION_TIMEOUT_SEC");
            break;
        case CONFIG_UDP_TIMEOUT_SEC:
            snprintf(str_out, str_len, "UDP_CONNECTION_TIMEOUT_SEC");
            break;
        case CONFIG_STATE_TABLE_CLEAN_INTERVAL:
            snprintf(str_out, str_len, "STATE_TABLE_CLEAN_INTERVAL_SEC");
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}

bool rule_chain_to_string(ChainType chain, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    switch (chain) {
        case CHAIN_INPUT:
            snprintf(str_out, str_len, "INPUT");
            break;
        case CHAIN_OUTPUT:
            snprintf(str_out, str_len, "OUTPUT");
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}

bool rule_protocol_to_string(ProtocolType proto, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    switch (proto) {
        case PROTO_ANY:
            snprintf(str_out, str_len, "ANY");
            break;
        case PROTO_ICMP:
            snprintf(str_out, str_len, "ICMP");
            break;
        case PROTO_TCP:
            snprintf(str_out, str_len, "TCP");
            break;
        case PROTO_UDP:
            snprintf(str_out, str_len, "UDP");
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}

bool rule_port_to_string(int port, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    if (port == -1) {
        snprintf(str_out, str_len, "ANY");
    } else if (port < 0 || port > 65535) {
        return false;
    } else {
        snprintf(str_out, str_len, "%d", port);
    }

    return true;
}

bool rule_action_to_string(ActionType action, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    switch (action) {
        case ACTION_ACCEPT:
            snprintf(str_out, str_len, "ACCEPT");
            break;
        case ACTION_DROP:
            snprintf(str_out, str_len, "DROP");
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}

bool rule_log_to_string(LogStatus log, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    switch (log) {
        case LOG_ENABLED:
            snprintf(str_out, str_len, "LOG");
            break;
        case LOG_DISABLED:
            snprintf(str_out, str_len, "NOLOG");
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}

bool rule_state_to_string(RuleState state, char *str_out, size_t str_len)
{
    if (str_out == NULL) {
        errno = EINVAL;
        return false;
    }

    switch (state) {
        case RULE_ENABLED:
            snprintf(str_out, str_len, "ENABLED");
            break;
        case RULE_DISABLED:
            snprintf(str_out, str_len, "DISABLED");
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    return true;
}

int parse_config_number(const char *config_number, int min_num)
{
    char *endptr;
    long ret = strtol(config_number, &endptr, 10);
    if (*endptr != '\0') {
        return min_num - 1;
    } else if (ret < min_num || ret > INT_MAX) {
        return min_num - 1;
    }

    return ret;
}

ConfigType parse_config_string(const char *config_string)
{
    if (config_string == NULL) {
        errno = EINVAL;
        return CONFIG_UNKNOWN;
    }

    if (strcmp(config_string, "INPUT_POLICY") == 0) {
        return CONFIG_INPUT_POLICY;
    }
    if (strcmp(config_string, "OUTPUT_POLICY") == 0) {
        return CONFIG_OUTPUT_POLICY;
    }
    if (strcmp(config_string, "DEFAULT_LOGGING") == 0) {
        return CONFIG_DEFAULT_LOGGING;
    }
    if (strcmp(config_string, "LOGFILE_ROTATE") == 0) {
        return CONFIG_LOGFILE_ROTATE;
    }
    if (strcmp(config_string, "LOG_ROTATION_SIZE_MB") == 0) {
        return CONFIG_LOG_ROTATION_SIZE;
    }
    if (strcmp(config_string, "ICMP_CONNECTION_TIMEOUT_SEC") == 0) {
        return CONFIG_ICMP_TIMEOUT_SEC;
    }
    if (strcmp(config_string, "TCP_CONNECTION_TIMEOUT_SEC") == 0) {
        return CONFIG_TCP_TIMEOUT_SEC;
    }
    if (strcmp(config_string, "UDP_CONNECTION_TIMEOUT_SEC") == 0) {
        return CONFIG_UDP_TIMEOUT_SEC;
    }
    if (strcmp(config_string, "STATE_TABLE_CLEAN_INTERVAL_SEC") == 0) {
        return CONFIG_STATE_TABLE_CLEAN_INTERVAL;
    }

    return CONFIG_UNKNOWN;
}

ChainType parse_chain_string(const char *chain_str)
{
    if (chain_str == NULL) {
        errno = EINVAL;
        return CHAIN_UNSPECIFIED;
    }

    if (strcmp(chain_str, "INPUT") == 0) {
        return CHAIN_INPUT;
    }
    if (strcmp(chain_str, "OUTPUT") == 0) {
        return CHAIN_OUTPUT;
    }

    return CHAIN_UNSPECIFIED;
}

ProtocolType parse_protocol_string(const char *proto_str)
{
    if (proto_str == NULL) {
        errno = EINVAL;
        return PROTO_UNSPECIFIED;
    }

    if (strcmp(proto_str, "ANY") == 0) {
        return PROTO_ANY;
    }
    if (strcmp(proto_str, "ICMP") == 0) {
        return PROTO_ICMP;
    }
    if (strcmp(proto_str, "TCP") == 0) {
        return PROTO_TCP;
    }
    if (strcmp(proto_str, "UDP") == 0) {
        return PROTO_UDP;
    }

    return PROTO_UNSPECIFIED;
}

ActionType parse_action_string(const char *action_str)
{
    if (action_str == NULL) {
        errno = EINVAL;
        return ACTION_UNSPECIFIED;
    }

    if (strcmp(action_str, "ACCEPT") == 0) {
        return ACTION_ACCEPT;
    }
    if (strcmp(action_str, "DROP") == 0) {
        return ACTION_DROP;
    }

    return ACTION_UNSPECIFIED;
}

LogStatus parse_log_string(const char *log_str)
{
    if (log_str == NULL) {
        errno = EINVAL;
        return LOG_UNSPECIFIED;
    }

    if (strcmp(log_str, "LOG") == 0) {
        return LOG_ENABLED;
    }
    if (strcmp(log_str, "NOLOG") == 0) {
        return LOG_DISABLED;
    }

    return LOG_UNSPECIFIED;
}

RuleState parse_state_string(const char *state_str)
{
    if (state_str == NULL) {
        errno = EINVAL;
        return RULE_UNSPECIFIED;
    }

    if (strcmp(state_str, "ENABLED") == 0) {
        return RULE_ENABLED;
    }
    if (strcmp(state_str, "DISABLED") == 0) {
        return RULE_DISABLED;
    }

    return RULE_UNSPECIFIED;
}

bool parse_rule_string(const char *str, FirewallRule *rule_out)
{
    char *copy = NULL;
    bool ret = false;

    if (str == NULL || rule_out == NULL) {
        goto cleanup;
    }

    // strtok_rは元の文字列を破壊するので、コピーを使う
    size_t copy_size = strlen(str) + 1;
    copy = malloc(copy_size);
    if (copy == NULL) {
        goto cleanup;
    }
    snprintf(copy, copy_size, "%s", str);
    copy[strcspn(copy, "\r\n")] = '\0';

    // ルールの原文を取得
    snprintf(rule_out->original, sizeof(rule_out->original), "%s", copy);

    // トークンを順次処理し、構造体を生成する
    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    rule_out->chain = parse_chain_string(token);
    if (rule_out->chain == CHAIN_UNSPECIFIED) {
        goto cleanup;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    rule_out->protocol = parse_protocol_string(token);
    if (rule_out->protocol == PROTO_UNSPECIFIED) {
        goto cleanup;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    if (is_valid_ip(token) == false) {
        goto cleanup;
    }
    snprintf(rule_out->src_ip, sizeof(rule_out->src_ip), "%s", token);

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    if (is_valid_port(token) == false) {
        goto cleanup;
    }
    if (rule_out->protocol == PROTO_ICMP && strcmp(token, "ANY") != 0) {
        goto cleanup;
    }
    if (strcmp(token, "ANY") == 0) {
        rule_out->src_port = -1;
    } else {
        rule_out->src_port = (int)strtol(token, NULL, 10);
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    if (is_valid_ip(token) == false) {
        goto cleanup;
    }
    snprintf(rule_out->dst_ip, sizeof(rule_out->dst_ip), "%s", token);

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    if (is_valid_port(token) == false) {
        goto cleanup;
    }
    if (rule_out->protocol == PROTO_ICMP && strcmp(token, "ANY") != 0) {
        goto cleanup;
    }
    if (strcmp(token, "ANY") == 0) {
        rule_out->dst_port = -1;
    } else {
        rule_out->dst_port = (int)strtol(token, NULL, 10);
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    rule_out->action = parse_action_string(token);
    if (rule_out->action == ACTION_UNSPECIFIED) {
        goto cleanup;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    rule_out->log = parse_log_string(token);
    if (rule_out->log == LOG_UNSPECIFIED) {
        goto cleanup;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (token == NULL) {
        goto cleanup;
    }
    rule_out->state = parse_state_string(token);
    if (rule_out->state == RULE_UNSPECIFIED) {
        goto cleanup;
    }

    ret = true;

    cleanup:
    free(copy);
    return ret;
}

bool format_rule_string(const FirewallRule *rule, char *str_out, size_t str_len)
{
    if (rule == NULL || str_out == NULL) {
        return false;
    }

    char chain[CHAIN_MAX_LEN];
    char protocol[PROTOCOL_MAX_LEN];
    char src_port[PORT_MAX_LEN];
    char dst_port[PORT_MAX_LEN];
    char action[ACTION_MAX_LEN];
    char log[LOG_STATUS_MAX_LEN];
    char state[RULE_STATE_MAX_LEN];

    if (rule_chain_to_string(rule->chain, chain,
                             sizeof(chain)) == false) {
        return false;
    }
    if (rule_protocol_to_string(rule->protocol, protocol,
                                sizeof(protocol)) == false) {
        return false;
    }
    if (rule_port_to_string(rule->src_port, src_port,
                            sizeof(src_port)) == false) {
        return false;
    }
    if (rule_port_to_string(rule->dst_port, dst_port,
                            sizeof(dst_port)) == false) {
        return false;
    }
    if (rule_action_to_string(rule->action, action,
                              sizeof(action)) == false) {
        return false;
    }
    if (rule_log_to_string(rule->log, log,
                           sizeof(log)) == false) {
        return false;
    }
    if (rule_state_to_string(rule->state, state,
                               sizeof(state)) == false) {
        return false;
    }

    int n = snprintf(
                str_out, str_len, "%s,%s,%s,%s,%s,%s,%s,%s,%s",
                chain, protocol, rule->src_ip, src_port,
                rule->dst_ip, dst_port, action, log, state
            );

    if (n < 0 || n >= str_len) {
        return false;
    }

    return true;
}