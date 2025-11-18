#ifndef FIREWALL_VALIDATION_H
#define FIREWALL_VALIDATION_H

#include <stdio.h>
#include <stdbool.h>
#include "firewall_config.h"

typedef enum {
    RULE_STR_VALID,            // 有効なルール文字列
    RULE_STR_INVALID_CHAIN,    // チェインの値が不正
    RULE_STR_INVALID_PROTOCOL, // プロトコルの値が不正
    RULE_STR_INVALID_SRC_IP,   // 送信元IPアドレスの値が不正
    RULE_STR_INVALID_DST_IP,   // 宛先IPアドレスの値が不正
    RULE_STR_INVALID_SRC_PORT, // 送信元ポート番号の値が不正
    RULE_STR_INVALID_DST_PORT, // 宛先ポート番号の値が不正
    RULE_STR_INVALID_ACTION,   // アクションの値が不正
    RULE_STR_INVALID_LOG,      // ログオプションの値が不正
    RULE_STR_INVALID_STATE,    // ルールのステータスの値が不正
    RULE_STR_ERR_ICMP_PORT,    // ICMPにポート番号を設定
    RULE_STR_ERR_INTERNAL      // 内部エラーが発生
} RuleValidationResult;

typedef enum {
    FILE_VALID,      // 有効なファイル
    FILE_NO_CONTENT, // ファイルにコンテンツが存在しない
    FILE_INVALID     // 無効なファイル
} FileValidationResult;

bool is_valid_ip(const char *ip_str);
bool is_valid_port(const char *port_str);
RuleValidationResult is_valid_rule_string(const char *rule_str);
FileValidationResult is_valid_rule_file(FILE *fp);

#endif