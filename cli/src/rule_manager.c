#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "firewall_parser.h"
#include "firewall_validation.h"
#include "rule_manager.h"

static RuleUpdateResult merge_rule(
    FirewallRule *src_rule,
    FirewallRule *dst_rule
);
static void print_header(ChainType chain, ActionType policy, LogStatus logging);
static bool print_rules(const FirewallRule *rules, size_t rule_len);
static void format_address_port(
    char *buf,
    size_t buf_size,
    const char *ip_str,
    int port_num, ProtocolType protocol
);

bool add_rule(FILE *fp, const FirewallRule *rule_to_add)
{
    if (fp == NULL || rule_to_add == NULL) {
        errno = EINVAL;
        return false;
    }

    char rule_str[RULE_MAX_LEN];
    if (strcmp(rule_to_add->original, ORIGINAL_UNSPECIFIED) != 0) {
        // FirewallRule構造体にルール文字列があればそれを使う
        snprintf(rule_str, sizeof(rule_str), "%s", rule_to_add->original);
    } else {
        // FirewallRule構造体を基にルール文字列を生成する
        if (format_rule_string(rule_to_add, rule_str,
                               sizeof(rule_str)) == false) {
            return false;
        }
    }

    fseek(fp, 0, SEEK_END);
    size_t len = strlen(rule_str);
    if (fwrite(rule_str, sizeof(char), len, fp) != len) {
        return false;
    }
    if (fwrite("\n", sizeof(char), 1, fp) != 1) {
        return false;
    }
    fseek(fp, 0, SEEK_SET);

    return true;
}

RuleUpdateResult update_rule(
    FILE *fp,
    FirewallRule *rule_to_update,
    ChainType target_chain,
    int target_index
)
{
    FirewallRule *rules = NULL;
    RuleUpdateResult ret = UPDATE_ERR_INTERNAL;

    if (fp == NULL || rule_to_update == NULL || target_index <= 0) {
        errno = EINVAL;
        goto cleanup;
    }

    RuleCounts counts;
    if (load_rules_from_file(fp, &rules, &counts) == false) {
        goto cleanup;
    }
    if (target_chain == CHAIN_INPUT) {
        if (counts.input_count == 0 || target_index > counts.input_count) {
            ret = UPDATE_ERR_INVALID_LINE_NUM;
            goto cleanup;
        }
    } else {
        if (counts.output_count == 0 || target_index > counts.output_count) {
            ret = UPDATE_ERR_INVALID_LINE_NUM;
            goto cleanup;
        }
    }

    // ターゲットルールのファイルの行番号を取得
    int chain_count = 0;
    int index = 0;
    for (int i = 0; i < counts.total_count; i++) {
        if (target_chain == rules[i].chain) {
            chain_count++;
            if (target_index == chain_count) {
                index = i;
                break;
            }
        }
    }
    FirewallRule *target_rule = &rules[index];

    // ターゲットルールを更新
    RuleUpdateResult merge_result =
        merge_rule(rule_to_update, target_rule);
    if (merge_result != UPDATE_SUCCESS) {
        ret = merge_result;
        goto cleanup;
    }

    // 更新後のルールが他のルールと重複していないか確認
    MatchLines match_lines;
    RuleExistsResult exists_result =
        rule_exists_in_file(fp, target_rule, &match_lines);
    switch (exists_result) {
        case RULE_NOT_FOUND:
            break;
        case RULE_MATCH:
            ret = ((index + 1) == match_lines.file_line)
                ? UPDATE_ERR_NO_CHANGE
                : UPDATE_ERR_DUPLICATE;
            goto cleanup;
            break; // NOT REACHED
        case RULE_CONFLICT:
            if ((index + 1) != match_lines.file_line) {
                ret = UPDATE_ERR_DUPLICATE;
                goto cleanup;
            }
            break;
        case RULE_ERROR:
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    // ルールをファイルに保存
    if (save_rules_to_file(fp, rules, counts.total_count) == false) {
        goto cleanup;
    }

    ret = UPDATE_SUCCESS;

    cleanup:
    free(rules);
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

static RuleUpdateResult merge_rule(
    FirewallRule *src_rule,
    FirewallRule *dst_rule
)
{
    if (src_rule == NULL || dst_rule == NULL) {
        errno = EINVAL;
        return UPDATE_ERR_INTERNAL;
    }

    if (src_rule->protocol != PROTO_UNSPECIFIED) {
        dst_rule->protocol = src_rule->protocol;
    }
    if (strcmp(src_rule->src_ip, IP_ADDR_UNSPECIFIED) != 0) {
        snprintf(dst_rule->src_ip, sizeof(dst_rule->src_ip),
                 "%s", src_rule->src_ip);
    }
    if (strcmp(src_rule->dst_ip, IP_ADDR_UNSPECIFIED) != 0) {
        snprintf(dst_rule->dst_ip, sizeof(dst_rule->dst_ip),
                 "%s", src_rule->dst_ip);
    }
    if (src_rule->src_port != PORT_UNSPECIFIED) {
        dst_rule->src_port = src_rule->src_port;
    }
    if (src_rule->dst_port != PORT_UNSPECIFIED) {
        dst_rule->dst_port = src_rule->dst_port;
    }
    if (src_rule->action != ACTION_UNSPECIFIED) {
        dst_rule->action = src_rule->action;
    }
    if (src_rule->log != LOG_UNSPECIFIED) {
        dst_rule->log = src_rule->log;
    }
    if (src_rule->state != RULE_UNSPECIFIED) {
        dst_rule->state = src_rule->state;
    }

    // ICMPにポート番号を設定しようとしていたらエラー
    if (dst_rule->protocol == PROTO_ICMP &&
        (dst_rule->src_port != -1 || dst_rule->dst_port != -1)) {
        return UPDATE_ERR_ICMP_PORT;
    }

    // ルールの原文をコピー
    char rule_str[RULE_MAX_LEN];
    if (format_rule_string(dst_rule, rule_str, sizeof(rule_str)) == false) {
        return UPDATE_ERR_INTERNAL;
    }
    snprintf(dst_rule->original, sizeof(dst_rule->original), "%s", rule_str);

    return UPDATE_SUCCESS;
}

RuleDeleteResult delete_rule(FILE *fp, ChainType target_chain, int target_index)
{
    char *buf = NULL;
    RuleDeleteResult ret = DELETE_ERR_INTERNAL;

    if (fp == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    if (target_index <= 0) {
        ret = DELETE_ERR_INVALID_LINE_NUM;
        goto cleanup;
    }

    RuleCounts counts;
    if (get_rule_counts_from_file(fp, &counts) == false) {
        goto cleanup;
    }
    if (target_chain == CHAIN_INPUT) {
        if (counts.input_count == 0 || target_index > counts.input_count) {
            ret = DELETE_ERR_INVALID_LINE_NUM;
            goto cleanup;
        }
    } else {
        if (counts.output_count == 0 || target_index > counts.output_count) {
            ret = DELETE_ERR_INVALID_LINE_NUM;
            goto cleanup;
        }
    }
    size_t buf_size = counts.total_count * RULE_MAX_LEN;
    buf = malloc(buf_size);
    if (buf == NULL) {
        goto cleanup;
    }

    int chain_count = 0;
    size_t offset = 0;
    bool found = false;
    char line[RULE_MAX_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        // strtok_rは元の文字列を破壊するので、コピーを使う
        char copy[RULE_MAX_LEN];
        snprintf(copy, sizeof(copy), "%s", line);

        char *saveptr = NULL;
        char *token = strtok_r(copy, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }

        if (found == false && target_chain == parse_chain_string(token)) {
            chain_count++;
            if (target_index == chain_count) {
                found = true;
                continue;
            }
        }

        int n = snprintf(buf + offset, buf_size - offset, "%s\n", line);
        if (n >= buf_size - offset) {
            goto cleanup;
        }
        offset += n;
    }

    int fd = fileno(fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (ftruncate(fd, 0) == -1) {
        goto cleanup;
    }
    fseek(fp, 0, SEEK_SET);
    if (fwrite(buf, sizeof(char), offset, fp) != offset) {
        goto cleanup;
    }

    ret = DELETE_SUCCESS;

    cleanup:
    free(buf);
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

bool show_rules(FILE *rule_fp, FILE *config_fp)
{
    FirewallRule *input_rules = NULL;
    FirewallRule *output_rules = NULL;
    bool ret = false;

    if (rule_fp == NULL || config_fp == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    FirewallConfig config;
    if (load_config_from_file(config_fp, &config) == false) {
        goto cleanup;
    }

    RuleCounts counts;
    if (load_rules_by_chain(rule_fp, &input_rules, &output_rules,
                            &counts) == false) {
        goto cleanup;
    }

    // INPUTチェインのルール表示
    print_header(CHAIN_INPUT, config.input_policy, config.default_logging);
    if (counts.input_count != 0) {
        if (print_rules(input_rules, counts.input_count) == false) {
            goto cleanup;
        }
    }
    printf("\n");

    // OUTPUTチェインのルール表示
    print_header(CHAIN_OUTPUT, config.output_policy, config.default_logging);
    if (counts.output_count != 0) {
        if (print_rules(output_rules, counts.output_count) == false) {
            goto cleanup;
        }
    }
    printf("\n");

    ret = true;

    cleanup:
    free(input_rules);
    free(output_rules);
    if (rule_fp != NULL) {
        fseek(rule_fp, 0, SEEK_SET);
    }
    if (config_fp != NULL) {
        fseek(config_fp, 0, SEEK_SET);
    }
    return ret;
}

static void print_header(ChainType chain, ActionType policy, LogStatus logging)
{
    char *chain_str = (chain == CHAIN_INPUT) ? "INPUT" : "OUTPUT";
    char *policy_str = (policy == ACTION_ACCEPT) ? "ACCEPT" : "DROP";
    char *logging_str = (logging == LOG_ENABLED) ? "ON" : "OFF";

    printf("%s (ポリシー：%s, デフォルトログ：%s)\n", chain_str, policy_str, logging_str);
    printf("%-6s  %-15s  %-28s  %-27s  %-15s  %-7s  %-10s\n",
           "番号", "プロトコル", "送信元アドレス", "宛先アドレス",
           "アクション", "ログ", "有効");
    printf("----  ----------  ---------------------  ---------------------  "
           "----------  -----  --------\n");
}

static bool print_rules(const FirewallRule *rules, size_t rule_len)
{
    if (rules == NULL) {
        return false;
    }

    for (int i = 0; i < rule_len; i++) {
        // ルール情報を文字列に変換
        char protocol[PROTOCOL_MAX_LEN];
        char action[ACTION_MAX_LEN];
        char src_addr[ADDR_PORT_MAX_LEN];
        char dst_addr[ADDR_PORT_MAX_LEN];
        char *log = (rules[i].log == LOG_ENABLED) ? "LOG" : "NOLOG";
        char *state = (rules[i].state == RULE_ENABLED) ? "ENABLED" : "DISABLED";
        if (rule_protocol_to_string(rules[i].protocol, protocol,
                                    sizeof(protocol)) == false) {
            return false;
        }
        if (rule_action_to_string(rules[i].action, action,
                                  sizeof(action)) == false) {
            return false;
        }
        format_address_port(src_addr, sizeof(src_addr), rules[i].src_ip,
                            rules[i].src_port, rules[i].protocol);
        format_address_port(dst_addr, sizeof(dst_addr), rules[i].dst_ip,
                            rules[i].dst_port, rules[i].protocol);

        // ルールの表示
        printf("%-4d  %-10s  %-21s  %-21s  %-10s  %-5s  %-8s\n",
               i + 1, protocol, src_addr, dst_addr, action, log, state);
    }

    return true;
}

static void format_address_port(char *buf, size_t buf_size,
                                const char *ip_str, int port_num,
                                ProtocolType protocol)
{
    if (protocol == PROTO_ICMP) {
        snprintf(buf, buf_size, "%s", ip_str);
        return;
    }

    if (port_num == -1) {
        snprintf(buf, buf_size, "%s:ANY", ip_str);
    } else {
        snprintf(buf, buf_size, "%s:%d", ip_str, port_num);
    }
}

RuleClearResult clear_rules(FILE *fp, ChainType target_chain)
{
    RuleCounts counts;
    FirewallRule *input_rules = NULL;
    FirewallRule *output_rules = NULL;
    RuleClearResult ret = CLEAR_ERR_INTERNAL;

    if (fp == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    int fd = fileno(fp);
    if (fd == -1) {
        goto cleanup;
    }

    switch (target_chain) {
        case CHAIN_INPUT:
            if (load_rules_by_chain(fp, NULL, &output_rules, &counts) == false) {
                goto cleanup;
            }

            if (counts.input_count == 0) {
                // INPUTチェインのルールが空の場合削除するルールがないのでエラー
                ret = CLEAR_ERR_NO_INPUT_RULES;
                goto cleanup;
            } else if (counts.output_count == 0) {
                // OUTPUTチェインのルールが空の場合すべてのルールを削除
                if (ftruncate(fd, 0) == -1) {
                    goto cleanup;
                }
            } else {
                // OUTPUTチェインのルールだけファイルに書き込むことで、
                // INPUTチェインのルールをクリアする
                if (save_rules_to_file(fp, output_rules, counts.output_count) == false) {
                    goto cleanup;
                }
            }
            break;
        case CHAIN_OUTPUT:
            if (load_rules_by_chain(fp, &input_rules, NULL, &counts) == false) {
                goto cleanup;
            }

            if (counts.output_count == 0) {
                // OUTPUTチェインのルールが空の場合削除するルールがないのでエラー
                ret = CLEAR_ERR_NO_OUTPUT_RULES;
                goto cleanup;
            } else if (counts.input_count == 0) {
                // INPUTチェインのルールが空の場合すべてのルールを削除
                if (ftruncate(fd, 0) == -1) {
                    goto cleanup;
                }
            } else {
                // INPUTチェインのルールだけファイルに書き込むことで、
                // OUTPUTチェインのルールをクリアする
                if (save_rules_to_file(fp, input_rules, counts.input_count) == false) {
                    goto cleanup;
                }
            }
            break;
        case CHAIN_UNSPECIFIED:
            if (get_rule_counts_from_file(fp, &counts) == false) {
                goto cleanup;
            }

            if (counts.total_count == 0) {
                ret = CLEAR_ERR_NO_RULES;
                goto cleanup;
            } else {
                if (ftruncate(fd, 0) == -1) {
                    goto cleanup;
                }
            }
            break;
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    ret = CLEAR_SUCCESS;

    cleanup:
    free(input_rules);
    free(output_rules);
    return ret;
}