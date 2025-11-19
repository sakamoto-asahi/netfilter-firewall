#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "firewall_validation.h"
#include "firewall_parser.h"
#include "firewall_rule.h"

bool load_config_from_file(FILE *fp, FirewallConfig *config_out)
{
    bool ret = false;

    if (fp == NULL || config_out == NULL) {
        goto cleanup;
    }

    FirewallConfig config;
    config.input_policy = DEFAULT_POLICY;
    config.output_policy = DEFAULT_POLICY;
    config.default_logging = DEFAULT_LOGGING;
    config.logfile_rotate = DEFAULT_LOGFILE_ROTATE;
    config.log_rotation_size = DEFAULT_LOG_ROTATION_SIZE_MB;
    config.state_timeouts.icmp_timeout_sec = DEFAULT_ICMP_CONNECTION_TIMEOUT_SEC;
    config.state_timeouts.tcp_timeout_sec = DEFAULT_TCP_CONNECTION_TIMEOUT_SEC;
    config.state_timeouts.udp_timeout_sec = DEFAULT_UDP_CONNECTION_TIMEOUT_SEC;

    char line[CONFIG_MAX_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        // 空行やコメント行はスキップ
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char *saveptr = NULL;
        char *key = strtok_r(line, "=", &saveptr);
        char *value = strtok_r(NULL, "=", &saveptr);
        if (key == NULL || value == NULL) {
            goto cleanup;
        }

        ConfigType config_type = parse_config_string(key);
        switch (config_type) {
            case CONFIG_INPUT_POLICY:
                ActionType input_policy = parse_action_string(value);
                if (input_policy == ACTION_UNSPECIFIED) {
                    goto cleanup;
                }
                config.input_policy = input_policy;
                break;
            case CONFIG_OUTPUT_POLICY:
                ActionType output_policy = parse_action_string(value);
                if (output_policy == ACTION_UNSPECIFIED) {
                    goto cleanup;
                }
                config.output_policy = output_policy;
                break;
            case CONFIG_DEFAULT_LOGGING:
                LogStatus default_logging = parse_log_string(value);
                if (default_logging == LOG_UNSPECIFIED) {
                    goto cleanup;
                }
                config.default_logging = default_logging;
                break;
            case CONFIG_LOGFILE_ROTATE:
                int rotate_value = parse_config_number(value, 0);
                if (rotate_value < 0) {
                    goto cleanup;
                }
                config.logfile_rotate = (size_t)rotate_value;
                break;
            case CONFIG_LOG_ROTATION_SIZE:
                int rotation_size_value = parse_config_number(value, 1);
                if (rotation_size_value < 1) {
                    goto cleanup;
                }
                config.log_rotation_size = (size_t)rotation_size_value;
                break;
            case CONFIG_ICMP_TIMEOUT_SEC:
                int icmp_timeout_value = parse_config_number(value, 0);
                if (icmp_timeout_value < 0) {
                    goto cleanup;
                }
                config.state_timeouts.icmp_timeout_sec = (size_t)icmp_timeout_value;
                break;
            case CONFIG_TCP_TIMEOUT_SEC:
                int tcp_timeout_value = parse_config_number(value, 0);
                if (tcp_timeout_value < 0) {
                    goto cleanup;
                }
                config.state_timeouts.tcp_timeout_sec = (size_t)tcp_timeout_value;
                break;
            case CONFIG_UDP_TIMEOUT_SEC:
                int udp_timeout_value = parse_config_number(value, 0);
                if (udp_timeout_value < 0) {
                    goto cleanup;
                }
                config.state_timeouts.udp_timeout_sec = (size_t)udp_timeout_value;
                break;
            case CONFIG_UNKNOWN:
                goto cleanup;
                break; // NOT REACHED
            default:
                goto cleanup;
                break; // NOT REACHED
        }
    }

    ret = true;

    cleanup:
    if (ret == true) {
        memcpy(config_out, &config, sizeof(FirewallConfig));
    }
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

bool reload_config(const char *filepath, FirewallConfig *config_out)
{
    FILE *fp = NULL;
    int fd = -1;
    bool ret = false;

    if (filepath == NULL || config_out == NULL) {
        goto cleanup;
    }

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        goto cleanup;
    }
    fd = fileno(fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_SH) == -1) {
        goto cleanup;
    }

    if (load_config_from_file(fp, config_out) == false) {
        goto cleanup;
    }

    ret = true;

    cleanup:
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

bool load_rules_from_file(
    FILE *fp,
    FirewallRule **rules_out,
    RuleCounts *rule_counts_out
)
{
    FirewallRule *rules = NULL;
    bool ret = false;

    if (fp == NULL || rules_out == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    // ルールの数と最大ルール長に基づいてメモリを確保
    RuleCounts counts;
    if (get_rule_counts_from_file(fp, &counts) == false) {
        goto cleanup;
    }
    if (counts.total_count == 0) {
        ret = true;
        goto cleanup;
    }
    size_t rules_size = sizeof(FirewallRule) * counts.total_count;
    rules = malloc(rules_size);
    if (rules == NULL) {
        goto cleanup;
    }

    char line[RULE_MAX_LEN];
    int line_count = 0;
    // ルール文字列から構造体を取得する
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (parse_rule_string(line, &rules[line_count]) == false) {
            goto cleanup;
        }
        line_count++;
    }

    ret = true;

    cleanup:
    if (rule_counts_out != NULL) {
        rule_counts_out->input_count = (ret == true) ? counts.input_count : 0;
        rule_counts_out->output_count = (ret == true) ? counts.output_count : 0;
        rule_counts_out->total_count = (ret == true) ? counts.total_count : 0;
    }
    *rules_out = (ret == true) ? rules : NULL;
    if (ret == false) {
        free(rules);
    }
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

bool load_rules_by_chain(
    FILE *fp,
    FirewallRule **input_rules_out,
    FirewallRule **output_rules_out,
    RuleCounts *rule_counts_out
)
{
    FirewallRule *input_rules = NULL;
    FirewallRule *output_rules = NULL;
    bool ret = false;

    if (fp == NULL || (input_rules_out == NULL && output_rules_out == NULL)) {
        errno = EINVAL;
        goto cleanup;
    }

    // ルールの数と最大ルール長に基づいてメモリを確保
    RuleCounts counts;
    if (get_rule_counts_from_file(fp, &counts) == false) {
        goto cleanup;
    }
    if (counts.total_count == 0) {
        ret = true;
        goto cleanup;
    }
    size_t input_rules_size = sizeof(FirewallRule) * counts.input_count;
    size_t output_rules_size = sizeof(FirewallRule) * counts.output_count;
    if (input_rules_size > 0) {
        input_rules = malloc(input_rules_size);
        if (input_rules == NULL) {
            goto cleanup;
        }
    } else {
        input_rules = NULL;
    }
    if (output_rules_size > 0) {
        output_rules = malloc(output_rules_size);
        if (output_rules == NULL) {
            goto cleanup;
        }
    } else {
        output_rules = NULL;
    }

    int input_count = 0;
    int output_count = 0;
    char line[RULE_MAX_LEN];
    // チェイン別にルール文字列から構造体を取得する
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        // strtok_rは元の文字列を破壊するので、コピーを使う
        char copy[RULE_MAX_LEN];
        snprintf(copy, sizeof(copy), "%s", line);

        // トークンからチェインを取得する
        char *saveptr = NULL;
        char *token = strtok_r(copy, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }

        if (strcmp(token, "INPUT") == 0) {
            if (input_count >= counts.input_count) {
                goto cleanup;
            }

            if (parse_rule_string(line, &input_rules[input_count]) == false) {
                goto cleanup;
            }
            input_count++;
        } else {
            if (output_count >= counts.output_count) {
                goto cleanup;
            }

            if (parse_rule_string(line, &output_rules[output_count]) == false) {
                goto cleanup;
            }
            output_count++;
        }
    }

    ret = true;

    cleanup:
    if (rule_counts_out != NULL) {
        rule_counts_out->input_count = (ret == true) ? counts.input_count : 0;
        rule_counts_out->output_count = (ret == true) ? counts.output_count : 0;
        rule_counts_out->total_count = (ret == true) ? counts.total_count : 0;
    }
    if (ret == true) {
        if (input_rules_out != NULL) {
            *input_rules_out = input_rules;
        } else {
            free(input_rules);
        }
        if (output_rules_out != NULL) {
            *output_rules_out = output_rules;
        } else {
            free(output_rules);
        }
    } else {
        free(input_rules);
        free(output_rules);
        if (input_rules_out != NULL) {
            *input_rules_out = NULL;
        }
        if (output_rules_out != NULL) {
            *output_rules_out = NULL;
        }
    }
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

bool reload_rules(
    const char *filepath,
    FirewallRule **input_rules_out,
    FirewallRule **output_rules_out,
    RuleCounts *rule_counts_out
)
{
    FILE *fp = NULL;
    int fd = -1;
    bool ret = false;

    if (input_rules_out == NULL || output_rules_out == NULL) {
        goto cleanup;
    }

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        goto cleanup;
    }
    fd = fileno(fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_SH) == -1) {
        goto cleanup;
    }

    FirewallRule *input_rules_tmp = *input_rules_out;
    FirewallRule *output_rules_tmp = *output_rules_out;

    if (load_rules_by_chain(fp, input_rules_out, output_rules_out,
                            rule_counts_out) == false) {
        goto cleanup;
    }

    free(input_rules_tmp);
    free(output_rules_tmp);

    ret = true;

    cleanup:
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

bool save_rules_to_file(
    FILE *fp,
    const FirewallRule *rules_to_save,
    size_t rule_len
)
{
    char *buf = NULL;
    bool ret = false;

    if (fp == NULL || rules_to_save == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    size_t buf_size = rule_len * RULE_MAX_LEN;
    buf = malloc(buf_size);
    if (buf == NULL) {
        goto cleanup;
    }

    size_t offset = 0;
    for (int i = 0; i < rule_len; i++) {
        char rule_str[RULE_MAX_LEN];
        const FirewallRule *current_rule = &rules_to_save[i];

        if (strcmp(current_rule->original, ORIGINAL_UNSPECIFIED) != 0) {
            snprintf(rule_str, sizeof(rule_str), "%s", current_rule->original);
        } else {
            if (format_rule_string(current_rule, rule_str,
                                   sizeof(rule_str)) == false) {
                goto cleanup;
            }
        }

        int n = snprintf(buf + offset, buf_size - offset, "%s\n", rule_str);
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

    ret = true;

    cleanup:
    free(buf);
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

RuleExistsResult rule_exists_in_file(
    FILE *fp,
    const FirewallRule *target_rule,
    MatchLines *match_lines_out
)
{
    RuleExistsResult ret = RULE_ERROR;

    if (fp == NULL || target_rule == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    int line_count = 0;
    int input_count = 0;
    int output_count = 0;
    char line[RULE_MAX_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_count++;
        line[strcspn(line, "\r\n")] = '\0';

        // トークンを順次処理し、重複チェックを行う
        char *saveptr = NULL;
        char *token = strtok_r(line, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        ChainType chain = parse_chain_string(token);
        if (chain == CHAIN_INPUT) {
            input_count++;
        } else if (chain == CHAIN_OUTPUT) {
            output_count++;
        } else {
            goto cleanup;
        }
        if (chain != target_rule->chain) {
            continue;
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (parse_protocol_string(token) != target_rule->protocol) {
            continue;
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (strcmp(token, target_rule->src_ip) != 0) {
            continue;
        }

        int src_port;
        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (strcmp(token, "ANY") == 0) {
            src_port = -1;
        } else {
            src_port = (int)strtol(token, NULL, 10);
        }
        if (src_port != target_rule->src_port) {
            continue;
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (strcmp(token, target_rule->dst_ip) != 0) {
            continue;
        }

        int dst_port;
        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (strcmp(token, "ANY") == 0) {
            dst_port = -1;
        } else {
            dst_port = (int)strtol(token, NULL, 10);
        }
        if (dst_port != target_rule->dst_port) {
            continue;
        }

        // この時点で基本情報（チェイン、プロトコル、IP、ポート）が一致するルールを発見

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (parse_action_string(token) != target_rule->action) {
            ret = RULE_CONFLICT;
            goto cleanup;
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (parse_log_string(token) != target_rule->log) {
            ret = RULE_CONFLICT;
            goto cleanup;
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }
        if (parse_state_string(token) != target_rule->state) {
            ret = RULE_CONFLICT;
            goto cleanup;
        }

        ret = RULE_MATCH;
        goto cleanup;
    }

    ret = RULE_NOT_FOUND;

    cleanup:
    if (match_lines_out != NULL) {
        if (ret == RULE_MATCH || ret == RULE_CONFLICT) {
            match_lines_out->file_line = line_count;
            // ターゲットチェインに対応するインデックスのみをセット
            if (target_rule->chain == CHAIN_INPUT) {
                match_lines_out->input_line = input_count;
                match_lines_out->output_line = 0;
            } else if (target_rule->chain == CHAIN_OUTPUT) {
                match_lines_out->input_line = 0;
                match_lines_out->output_line = output_count;
            }
        } else if (ret == RULE_NOT_FOUND) {
            match_lines_out->file_line = 0;
            match_lines_out->input_line = 0;
            match_lines_out->output_line = 0;
        } else {
            match_lines_out->file_line = -1;
            match_lines_out->input_line = -1;
            match_lines_out->output_line = -1;
        }
    }
    if (fp != NULL) {
        fseek(fp, 0 ,SEEK_SET);
    }
    return ret;
}

ConfigChangeResult change_config(
    FILE *fp,
    const char *target_key,
    const char *target_value
)
{
    char *buf = NULL;
    ConfigChangeResult ret = CONFIG_CHANGE_ERR_INTERNAL;

    if (fp == NULL || target_key == NULL || target_value == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    // ファイルサイズと最大設定文字列に基づいてバッファを確保
    int fd = fileno(fp);
    if (fd == -1) {
        goto cleanup;
    }
    struct stat st;
    if (fstat(fd, &st) == -1) {
        goto cleanup;
    }
    size_t buf_size = st.st_size + CONFIG_MAX_LEN;
    buf = malloc(buf_size);
    if (buf == NULL) {
        goto cleanup;
    }

    bool exists = false;
    size_t offset = 0;
    char line[CONFIG_MAX_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';

        // strtok_rは元の文字列を破壊するので、コピーを使う
        char copy[CONFIG_MAX_LEN];
        snprintf(copy, sizeof(copy), "%s", line);

        // 空行やコメント行はスキップ
        if (copy[0] == '\0' || copy[0] == '#') {
            continue;
        }

        char *saveptr = NULL;
        char *key = strtok_r(copy, "=", &saveptr);
        char *value = strtok_r(NULL, "=", &saveptr);
        if (key == NULL || value == NULL) {
            goto cleanup;
        }

        if (strcmp(key, target_key) == 0) {
            if (strcmp(value, target_value) == 0) {
                ret = CONFIG_CHANGE_ERR_NO_CHANGE;
                goto cleanup;
            }
            snprintf(line, sizeof(line), "%s=%s", target_key, target_value);
            exists = true;
        }

        int n = snprintf(buf + offset, buf_size - offset, "%s\n", line);
        if (n >= buf_size - offset) {
            goto cleanup;
        }
        offset += n;
    }

    // 設定が存在しなければ、新しく追加する
    if (exists == false) {
        int n = snprintf(buf + offset, buf_size - offset, "%s=%s\n",
                         target_key, target_value);
        if (n >= buf_size - offset) {
            goto cleanup;
        }
        offset += n;
    }

    if (ftruncate(fd, 0) == -1) {
        goto cleanup;
    }
    fseek(fp, 0, SEEK_SET);
    if (fwrite(buf, sizeof(char), offset, fp) != offset) {
        goto cleanup;
    }

    ret = CONFIG_CHANGE_SUCCESS;

    cleanup:
    free(buf);
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return ret;
}

bool get_rule_counts_from_file(FILE *fp, RuleCounts *counts_out)
{
    bool ret = false;

    if (fp == NULL || counts_out == NULL) {
        goto cleanup;
    }

    int input_count = 0;
    int output_count = 0;
    char line[RULE_MAX_LEN];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *saveptr = NULL;
        char *token = strtok_r(line, ",", &saveptr);
        if (token == NULL) {
            goto cleanup;
        }

        ChainType chain = parse_chain_string(token);
        switch (chain) {
            case CHAIN_INPUT:
                input_count++;
                break;
            case CHAIN_OUTPUT:
                output_count++;
                break;
            case CHAIN_UNSPECIFIED:
            default:
                goto cleanup;
                break; // NOT REACHED
        }
    }

    ret = true;

    cleanup:
    counts_out->input_count = (ret == true) ? input_count : 0;
    counts_out->output_count = (ret == true) ? output_count : 0;
    counts_out->total_count = (ret == true) ? input_count + output_count : 0;
    if (fp != NULL) {
        fseek(fp, 0, SEEK_SET);
    }
    return true;
}

bool copy_file(FILE *src_fp, FILE *dst_fp)
{
    char *buf = NULL;
    bool ret = false;

    if (src_fp == NULL || dst_fp == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    // ファイルサイズに基づいてバッファを確保
    int src_fd = fileno(src_fp);
    if (src_fd == -1) {
        goto cleanup;
    }
    struct stat st;
    if (fstat(src_fd, &st) == -1) {
        goto cleanup;
    }
    size_t buf_size = st.st_size;
    buf = malloc(buf_size);
    if (buf == NULL) {
        goto cleanup;
    }

    if (fread(buf, sizeof(char), buf_size, src_fp) != buf_size) {
        goto cleanup;
    }
    int dst_fd = fileno(dst_fp);
    if (dst_fd == -1) {
        goto cleanup;
    }
    if (ftruncate(dst_fd, 0) == -1) {
        goto cleanup;
    }
    fseek(dst_fp, 0, SEEK_SET);
    if (fwrite(buf, sizeof(char), buf_size, dst_fp) != buf_size) {
        goto cleanup;
    }

    ret = true;

    cleanup:
    if (src_fp != NULL) {
        fseek(src_fp, 0, SEEK_SET);
    }
    if (dst_fp != NULL) {
        fseek(dst_fp, 0, SEEK_SET);
    }
    free(buf);
    return ret;
}