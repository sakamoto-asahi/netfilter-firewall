#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "firewall_config.h"
#include "firewall_init.h"
#include "firewall_validation.h"
#include "firewall_parser.h"
#include "firewall_rule.h"
#include "command/add_command.h"
#include "command/update_command.h"
#include "command/show_command.h"
#include "command/delete_command.h"
#include "command/clear_command.h"
#include "command/import_command.h"
#include "command/export_command.h"
#include "command/change_policy_command.h"
#include "command/logging_command.h"
#include "command/reload_config_command.h"
#include "command/shutdown_command.h"

typedef enum {
    CMD_ADD,
    CMD_UPDATE,
    CMD_SHOW,
    CMD_DELETE,
    CMD_CLEAR,
    CMD_IMPORT,
    CMD_EXPORT,
    CMD_CHANGE_POLICY,
    CMD_LOGGING,
    CMD_RELOAD,
    CMD_HELP,
    CMD_SHUTDOWN,
    CMD_UNKNOWN
} CommandType;

static void print_usage(void);
static CommandType parse_command(const char *cmd);

static struct option longopts[] = {
    {"chain", required_argument, NULL, 'c'},
    {"protocol", required_argument, NULL, 'p'},
    {"src-ip", required_argument, NULL, 's'},
    {"dst-ip", required_argument, NULL, 'd'},
    {"src-port", required_argument, NULL, 'S'},
    {"dst-port", required_argument, NULL, 'D'},
    {"action", required_argument, NULL, 'a'},
    {"log", required_argument, NULL, 'l'},
    {"rule", required_argument, NULL, 'r'},
    {0,0,0,0}
};

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "エラー：コマンドを指定してください。\n");
        print_usage();
        return 1;
    }

    if (init_env() == false) {
        fprintf(stderr, "予期せぬエラーが発生しました。\n");
        return 1;
    }

    opterr = 0; // 日本語でエラーを出すために、標準のエラーを抑制
    char *cmd = argv[1];
    char *arg = argv[2];
    FirewallRule rule;
    init_rule_struct(&rule);

    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:s:d:S:D:a:l:r:",
                              longopts, NULL)) != -1) {
        switch (opt) {
            case 'c': // チェイン
                ChainType chain = parse_chain_string(optarg);
                if (chain == CHAIN_UNSPECIFIED) {
                    fprintf(stderr, "エラー：チェインが不正な値です。\n");
                    return false;
                }
                rule.chain = chain;
                break;
            case 'p': // プロトコル
                ProtocolType protocol = parse_protocol_string(optarg);
                if (protocol == PROTO_UNSPECIFIED) {
                    fprintf(stderr, "エラー：プロトコルが不正な値です。\n");
                    return false;
                }
                rule.protocol = protocol;
                break;
            case 's': // 送信元IPアドレス
                if (is_valid_ip(optarg) == false) {
                    fprintf(stderr, "エラー：送信元IPアドレスの値が不正です。\n");
                    return false;
                }
                snprintf(rule.src_ip, sizeof(rule.src_ip), "%s", optarg);
                break;
            case 'd': // 宛先IPアドレス
                if (is_valid_ip(optarg) == false) {
                    fprintf(stderr, "エラー：宛先IPアドレスの値が不正です。\n");
                    return false;
                }
                snprintf(rule.dst_ip, sizeof(rule.dst_ip), "%s", optarg);
                break;
            case 'S': // 送信元ポート番号
                if (is_valid_port(optarg) == false) {
                    fprintf(stderr, "エラー：送信元ポート番号の値が不正です。\n");
                    return false;
                }
                if (strcmp(optarg, "ANY") == 0) {
                    rule.src_port = -1;
                } else {
                    rule.src_port = (int)strtol(optarg, NULL, 10);
                }
                break;
            case 'D': // 宛先ポート番号
                if (is_valid_port(optarg) == false) {
                    fprintf(stderr, "エラー：宛先ポート番号の値が不正です。\n");
                    return false;
                }
                if (strcmp(optarg, "ANY") == 0) {
                    rule.dst_port = -1;
                } else {
                    rule.dst_port = (int)strtol(optarg, NULL, 10);
                }
                break;
            case 'a': // アクション
                ActionType action = parse_action_string(optarg);
                if (action == ACTION_UNSPECIFIED) {
                    fprintf(stderr, "エラー：アクションの値が不正です。\n");
                    return false;
                }
                rule.action = action;
                break;
            case 'l': // ログオプション
                if (parse_log_string(optarg) == LOG_UNSPECIFIED) {
                    fprintf(stderr, "エラー：ログオプションの値が不正です。\n");
                    return false;
                }
                rule.log = (strcmp(optarg, "LOG") == 0)
                    ? LOG_ENABLED
                    : LOG_DISABLED;
                break;
            case 'r': // ルールの有効・無効
                if (parse_state_string(optarg) == RULE_UNSPECIFIED) {
                    fprintf(stderr, "エラー：ルールの有効化に関する値が不正です。\n");
                    return false;
                }
                rule.state = (strcmp(optarg, "ENABLED") == 0)
                    ? RULE_ENABLED
                    : RULE_DISABLED;
                break;
            default:
                if ('p' == optopt || 's' == optopt || 'S' == optopt ||
                    'd' == optopt || 'D' == optopt || 'a' == optopt ||
                    'l' == optopt || 'r' == optopt) {
                    fprintf(stderr, "エラー：オプション -%c には引数が必要です。\n", optopt);
                } else {
                    fprintf(stderr, "エラー：-%c は不明なオプションです。\n", optopt);
                }
                return 1;
                break; // NOT REACHED
        }
    }

    CommandType ctype = parse_command(cmd);
    switch (ctype) {
        case CMD_ADD:
            if (add_command(RULE_FILE, &rule) == false) {
                return 1;
            }
            break;
        case CMD_UPDATE:
            if (update_command(RULE_FILE, &rule, rule.chain, arg) == false) {
                return 1;
            }
            break;
        case CMD_SHOW:
            if (show_command(RULE_FILE, FIREWALL_CONFIG_FILE) == false) {
                return 1;
            }
            break;
        case CMD_DELETE:
            if (delete_command(RULE_FILE, rule.chain, arg) == false) {
                return 1;
            }
            break;
        case CMD_CLEAR:
            if (clear_command(RULE_FILE, rule.chain) == false) {
                return 1;
            }
            break;
        case CMD_IMPORT:
            if (import_command(RULE_FILE, arg) == false) {
                return 1;
            }
            break;
        case CMD_EXPORT:
            if (export_command(RULE_FILE, arg) == false) {
                return 1;
            }
            break;
        case CMD_CHANGE_POLICY:
            if (change_policy_command(FIREWALL_CONFIG_FILE, rule.chain,
                                      rule.action) == false) {
                return 1;
            }
            break;
        case CMD_LOGGING:
            if (logging_command(FIREWALL_CONFIG_FILE, rule.log) == false) {
                return 1;
            }
            break;
        case CMD_RELOAD:
            if (reload_config_command() == false) {
                return 1;
            }
            break;
        case CMD_SHUTDOWN:
            if (shutdown_command() == false) {
                return 1;
            }
            break;
        case CMD_HELP:
            print_usage();
            break;
        case CMD_UNKNOWN:
        default:
            fprintf(stderr, "エラー：%sというコマンドは存在しません。\n", cmd);
            print_usage();
            break;
    }
    return 0;
}

static void print_usage(void)
{
    printf("使用方法：nfw-ctl <コマンド> [オプション]\n");
    printf("コマンド一覧：\n");
    printf("  add       新しいフィルタリングルールを追加します。\n");
    printf("            引数にオプションでルールを指定します。\n\n");
    printf("  update    指定した行番号のルールを更新します。\n");
    printf("            引数に行番号とチェイン（-c）、更新内容を指定します。\n\n");
    printf("  show      現在のフィルタリングルールを表示します。\n\n");
    printf("  delete    指定した行番号のルールを削除します。\n");
    printf("            引数に行番号とチェイン（-c）を指定します。\n\n");
    printf("  clear     すべてのフィルタリングルールを削除します。\n");
    printf("            特定のチェインのルールだけを削除する場合、引数にチェイン（-c）を指定します。\n\n");
    printf("  import    外部ファイルからルールを読み込み、現在のルールに上書きします。\n");
    printf("            引数に外部のルールファイルのパスを指定します。\n\n");
    printf("  export    現在のルールを指定したファイルに出力します。\n");
    printf("            引数に出力先ファイルのパスを指定します。\n\n");
    printf("  policy    デフォルトポリシーを変更します。\n");
    printf("            引数にチェイン（-c）とアクション（-a）を指定します。\n\n");
    printf("  logging   デフォルトのログ設定を指定します。\n");
    printf("            引数にログ設定（-l）を指定します。\n\n");
    printf("  reload    設定ファイルを再読み込みし、設定を適用します。\n\n");
    printf("  shutdown  ファイアウォール本体をシャットダウンします。\n\n");
    printf("  help      このヘルプメッセージを表示します。\n\n");
    printf("\n");
    printf("オプション一覧：\n");
    printf("  -c, --chain      <INPUT|OUTPUT>      チェインを指定\n");
    printf("  -p, --protocol   <ICMP|TCP|UDP>      プロトコルを指定\n");
    printf("  -s, --src-ip     <IPアドレス>        送信元IPアドレスを指定\n");
    printf("  -S, --src-port   <ポート番号>        送信元ポート番号を指定\n");
    printf("  -d, --dst-ip     <IPアドレス>        宛先IPアドレスを指定\n");
    printf("  -D, --dst-port   <ポート番号>        宛先ポート番号を指定\n");
    printf("  -a, --action     <ACCEPT|DROP>       パケットのアクションを指定\n");
    printf("  -l, --log        <LOG|NOLOG>         ログの有無を指定\n");
    printf("  -r, --rule       <ENABLED|DISABLED>  ルールの有効・無効を設定\n");
}

static CommandType parse_command(const char *cmd)
{
    if (strcmp(cmd, "add") == 0) {
        return CMD_ADD;
    }
    if (strcmp(cmd, "update") == 0) {
        return CMD_UPDATE;
    }
    if (strcmp(cmd, "show") == 0) {
        return CMD_SHOW;
    }
    if (strcmp(cmd, "delete") == 0) {
        return CMD_DELETE;
    }
    if (strcmp(cmd, "clear") == 0) {
        return CMD_CLEAR;
    }
    if (strcmp(cmd, "import") == 0) {
        return CMD_IMPORT;
    }
    if (strcmp(cmd, "export") == 0) {
        return CMD_EXPORT;
    }
    if (strcmp(cmd, "policy") == 0) {
        return CMD_CHANGE_POLICY;
    }
    if (strcmp(cmd, "logging") == 0) {
        return CMD_LOGGING;
    }
    if (strcmp(cmd, "reload") == 0) {
        return CMD_RELOAD;
    }
    if (strcmp(cmd, "shutdown") == 0) {
        return CMD_SHUTDOWN;
    }
    if (strcmp(cmd, "help") == 0) {
        return CMD_HELP;
    }
    return CMD_UNKNOWN;
}