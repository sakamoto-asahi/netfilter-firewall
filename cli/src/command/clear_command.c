#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "rule_manager.h"
#include "domain_socket_utils.h"

bool clear_command(const char *filepath, ChainType target_chain)
{
    char *err_msg = "予期せぬエラーが発生したため、"
                    "ルールのクリアを完了できませんでした。";
    FILE *rule_fp = NULL;
    int fd = -1;
    bool ret = false;

    // 引数チェック
    if (filepath == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    // ファイルのオープンとロック
    rule_fp = fopen(filepath, "r+");
    if (rule_fp == NULL) {
        goto cleanup;
    }
    fd = fileno(rule_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }

    RuleClearResult clear_result = clear_rules(rule_fp, target_chain);
    switch (clear_result) {
        case CLEAR_SUCCESS:
            break;
        case CLEAR_ERR_NO_INPUT_RULES:
            err_msg = "エラー：INPUTチェインにルールは存在しません。";
            goto cleanup;
            break; // NOT REACHED
        case CLEAR_ERR_NO_OUTPUT_RULES:
            err_msg = "エラー：OUTPUTチェインにルールは存在しません。";
            goto cleanup;
            break; // NOT REACHED
        case CLEAR_ERR_NO_RULES:
            err_msg = "エラー：ルールは存在しません。";
            goto cleanup;
            break; // NOT REACHED
        case CLEAR_ERR_INTERNAL:
            goto cleanup;
            break; // NOT REACHED
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    // ファイアウォールがファイルを閲覧できるよう、共有ロックに変更
    if (flock(fd, LOCK_SH) == -1) {
        goto cleanup;
    }

    // ファイアウォール本体にルールの更新を伝える
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_RELOAD_RULES
    );
    switch (response) {
        case RES_SUCCESS:
            printf("ルールがすべて削除されました。\n");
            break;
        case RES_FAILURE:
            err_msg = "エラー：ファイアウォールがルールの再読み込みに失敗しました。";
            goto cleanup;
            break; // NOT REACHED
        case RES_TIMEOUT:
            err_msg = "エラー：ファイアウォールからの応答がタイムアウトしました。";
            goto cleanup;
            break; // NOT REACHED
        case RES_ERROR:
            err_msg = "エラー：ファイアウォールへの接続に失敗しました。";
            goto cleanup;
            break; // NOT REACHED
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    ret =  true;

    cleanup:
    if (ret == false) {
        fprintf(stderr, "%s\n", err_msg);
    }
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
    if (rule_fp != NULL) {
        fclose(rule_fp);
    }
    return ret;
}