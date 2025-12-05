#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include <stdio.h>
#include <stdbool.h>
#include "firewall_config.h"

typedef enum {
    UPDATE_SUCCESS,              // 成功
    UPDATE_ERR_NO_CHANGE,        // 更新前と更新後でルールが変わっていない
    UPDATE_ERR_DUPLICATE,        // 更新後のルールと同じルールが別の行に存在する
    UPDATE_ERR_ICMP_PORT,        // ICMPにポート番号を設定しようとしている
    UPDATE_ERR_INVALID_LINE_NUM, // ユーザが指定した行番号にルールが存在しない
    UPDATE_ERR_INTERNAL          // 内部エラーが発生
} RuleUpdateResult;

typedef enum {
    DELETE_SUCCESS,              // 成功
    DELETE_ERR_INVALID_LINE_NUM, // ユーザが指定した行番号にルールが存在しない
    DELETE_ERR_INTERNAL          // 内部エラーが発生
} RuleDeleteResult;

typedef enum {
    CLEAR_SUCCESS,
    CLEAR_ERR_NO_INPUT_RULES,
    CLEAR_ERR_NO_OUTPUT_RULES,
    CLEAR_ERR_NO_RULES,
    CLEAR_ERR_INTERNAL
} RuleClearResult;

bool add_rule(FILE *fp, const FirewallRule *rule_to_add);
RuleUpdateResult update_rule(
    FILE *fp,
    FirewallRule *rule_to_update,
    ChainType target_chain,
    int target_index
);
RuleDeleteResult delete_rule(
    FILE *fp,
    ChainType target_chain,
    int target_index
);
bool show_rules(FILE *rule_fp, FILE *config_fp);
RuleClearResult clear_rules(FILE *fp, ChainType target_chain);

#endif