#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "firewall_config.h"
#include "firewall_parser.h"

static bool format_icmp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy
);

static bool format_tcpudp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy
);

static bool format_other_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy
);

bool log_rotation(FILE **log_fp, size_t rotate, size_t rotation_size_mb);

void log_packet(
    FILE **log_fp,
    const unsigned char *packet,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy,
    size_t logfile_rotate,
    size_t log_rotation_size
)
{
    int fd = -1;

    if (log_fp == NULL || packet == NULL) {
        goto cleanup;
    }

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    char timestamp[64];
    char log[1024];

    // 現在時刻取得
    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local);

    // プロトコル別にログを取得
    switch (ip_hdr->protocol) {
        case IPPROTO_ICMP:
            if (format_icmp_log(packet, log, sizeof(log), timestamp, chain_type,
                                match_rule, policy) == false) {
                goto cleanup;
            }
            break;
        case IPPROTO_TCP: // TCPはUDPと同じ関数でログを取る
        case IPPROTO_UDP:
            if (format_tcpudp_log(packet, log, sizeof(log), timestamp, chain_type,
                                  match_rule, policy) == false) {
                goto cleanup;
            }
            break;
        default:
            if (format_other_log(packet, log, sizeof(log), timestamp, chain_type,
                                 match_rule, policy) == false) {
                goto cleanup;
            }
            break;
    }

    if (log_rotation(log_fp, logfile_rotate, log_rotation_size) == false) {
        goto cleanup;
    }

    // ファイルに書き込む
    fd = fileno(*log_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }
    ssize_t n = fwrite(log, sizeof(char), strlen(log), *log_fp);
    if (n == -1) {
        goto cleanup;
    }
    fflush(*log_fp);

    cleanup:
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
}

static bool format_icmp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ip_hdr->ihl * 4);
    char *chain = (chain_type == CHAIN_INPUT) ? "INPUT" : "OUTPUT";
    char *rule = (match_rule != NULL) ? match_rule->original : "NoRule";
    unsigned char type = icmp_hdr->type;
    unsigned char code = icmp_hdr->code;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char action[ACTION_MAX_LEN];
    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return false;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return false;
    }
    if (match_rule != NULL) {
        rule_action_to_string(match_rule->action, action, sizeof(action));
    } else {
        snprintf(
            action, sizeof(action),
            "%s", (policy = ACTION_ACCEPT) ? "ACCEPT" : "DROP"
        );
    }

    snprintf(
        log_out, log_len,
        "[%s] %s %s ICMP %s -> %s [TYPE: %d, CODE: %d] rule:[%s]\n",
        timestamp, chain, action, src_ip, dst_ip, type, code, rule
    );

    return true;
}

static bool format_tcpudp_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    char *chain = (chain_type == CHAIN_INPUT) ? "INPUT" : "OUTPUT";
    char *rule = (match_rule != NULL) ? match_rule->original : "NoRule";
    char *protocol = (ip_hdr->protocol == IPPROTO_TCP) ? "TCP" : "UDP";
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int src_port;
    int dst_port;
    char action[ACTION_MAX_LEN];
    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return false;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return false;
    }
    get_packet_ports(packet, &src_port, &dst_port);
    if (match_rule != NULL) {
        rule_action_to_string(match_rule->action, action, sizeof(action));
    } else {
        snprintf(
            action, sizeof(action),
            "%s", (policy = ACTION_ACCEPT) ? "ACCEPT" : "DROP"
        );
    }

    snprintf(
        log_out, log_len,
        "[%s] %s %s %s %s:%d -> %s:%d rule:[%s]\n",
        timestamp, chain, action, protocol, src_ip, src_port,
        dst_ip, dst_port, rule
    );

    return true;
}

static bool format_other_log(
    const unsigned char *packet,
    char *log_out,
    size_t log_len,
    const char *timestamp,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    char *chain = (chain_type == CHAIN_INPUT) ? "INPUT" : "OUTPUT";
    char *rule = (match_rule != NULL) ? match_rule->original : "NoRule";
    int proto_num = (int)ip_hdr->protocol;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char action[ACTION_MAX_LEN];
    if (inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, sizeof(src_ip)) == NULL) {
        return false;
    }
    if (inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, sizeof(dst_ip)) == NULL) {
        return false;
    }
    if (match_rule != NULL) {
        rule_action_to_string(match_rule->action, action, sizeof(action));
    } else {
        snprintf(
            action, sizeof(action),
            "%s", (policy = ACTION_ACCEPT) ? "ACCEPT" : "DROP"
        );
    }

    snprintf(
        log_out, log_len,
        "[%s] %s %s PROTOCOL NUMBER:%d %s -> %s rule:[%s]\n",
        timestamp, chain, action, proto_num, src_ip, dst_ip, rule
    );

    return true;
}

bool log_rotation(FILE **log_fp, size_t rotate, size_t rotation_size_mb)
{
    unsigned int rotation_size_bytes = rotation_size_mb * 1024 * 1024;
    struct stat st;
    if (stat(LOG_FILE, &st) == -1) {
        return false;
    }
    if (st.st_size < rotation_size_bytes) {
        // ファイルサイズが既定値未満なら何もせずに終了
        return true;
    }

    char logfile[LOG_FILE_MAX_LEN];
    snprintf(logfile, sizeof(logfile), "%s.", basename(LOG_FILE));
    DIR *dir = opendir(LOG_DIR);
    if (dir == NULL) {
        return false;
    }
    int logfile_count = 0;
    struct dirent *dp;
    while ((dp = readdir(dir)) != NULL) {
        if (strncmp(dp->d_name, logfile, strlen(logfile)) == 0) {
            logfile_count++;
        }
    }
    closedir(dir);

    // ログファイルのファイル名を一つずつずらす
    char src_filepath[LOG_FILE_MAX_LEN];
    char dst_filepath[LOG_FILE_MAX_LEN];
    for (int i = logfile_count; i >= 0; i--) {
        snprintf(src_filepath, sizeof(src_filepath), "%s.%d", LOG_FILE, i);
        snprintf(dst_filepath, sizeof(dst_filepath), "%s.%d", LOG_FILE, i + 1);

        if (i == rotate) {
            unlink(src_filepath);
        } else if (i == 0) {
            if (rename(LOG_FILE, dst_filepath) == -1) {
                return false;
            }
        } else {
            if (rename(src_filepath, dst_filepath) == -1) {
                return false;
            }
        }
    }

    // ファイルを開きなおす
    FILE *new_fp = freopen(LOG_FILE, "a", *log_fp);
    if (new_fp == NULL) {
        *log_fp = NULL;
        return false;
    }
    *log_fp = new_fp;

    return true;
}