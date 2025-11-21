#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_config.h"
#include "firewall_io.h"
#include "firewall_validation.h"
#include "firewall_parser.h"
#include "domain_socket_utils.h"

bool logging_command(const char *filepath, LogStatus logging)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ログの設定ができませんでした。";
    FILE *config_fp = NULL;
    FILE *tmp_fp = NULL;
    int fd = -1;
    bool ret = false;

    // 引数チェック
    if (filepath == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (logging == LOG_UNSPECIFIED) {
        err_msg = "エラー：-l オプションでログの設定を指定してください。";
        goto cleanup;
    }

    // ファイルのオープンとロック
    config_fp = fopen(filepath, "r");
    tmp_fp = fopen(TMP_FIREWALL_CONFIG_FILE, "w+");
    if (config_fp == NULL || tmp_fp == NULL) {
        goto cleanup;
    }
    fd = fileno(config_fp);
    if (fd == -1) {
        goto cleanup;
    }
    if (flock(fd, LOCK_EX) == -1) {
        goto cleanup;
    }

    if (copy_file(config_fp, tmp_fp) == false) {
        goto cleanup;
    }

    // ログ設定の変更
    char target_key[CONFIG_MAX_LEN];
    char target_value[CONFIG_MAX_LEN];
    if (config_to_string(CONFIG_DEFAULT_LOGGING, target_key,
                         sizeof(target_key)) == false) {
        goto cleanup;
    }
    if (rule_log_to_string(logging, target_value,
                           sizeof(target_value)) == false) {
        goto cleanup;
    }

    ConfigChangeResult change_result =
        change_config(tmp_fp, target_key, target_value);
    switch (change_result) {
        case CONFIG_CHANGE_SUCCESS:
            break;
        case CONFIG_CHANGE_ERR_NO_CHANGE:
            err_msg = "エラー：元のログ設定から変更されていません。";
            goto cleanup;
            break; // NOT REACHED
        case CONFIG_CHANGE_ERR_INTERNAL:
            goto cleanup;
            break; // NOT REACHED
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    fclose(tmp_fp);
    tmp_fp = NULL;
    if (rename(TMP_FIREWALL_CONFIG_FILE, filepath) == -1) {
        goto cleanup;
    }
    flock(fd, LOCK_UN);
    fclose(config_fp);
    fd = -1;
    config_fp = NULL;

    // ファイアウォール本体に設定の更新を伝える
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_RELOAD_CONFIG
    );
    switch (response) {
        case RES_SUCCESS:
            printf("ログ設定が更新されました。\n");
            break;
        case RES_FAILURE:
            err_msg = "エラー：ファイアウォールが設定の再読み込みに失敗しました。";
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

    ret = true;

    cleanup:
    if (ret == false) {
        fprintf(stderr, "%s\n", err_msg);
    }
    if (fd != -1) {
        flock(fd, LOCK_UN);
    }
    if (config_fp != NULL) {
        fclose(config_fp);
    }
    if (tmp_fp != NULL) {
        fclose(tmp_fp);
    }
    if (access(TMP_FIREWALL_CONFIG_FILE, F_OK) == 0) {
        unlink(TMP_FIREWALL_CONFIG_FILE);
    }
    return ret;
}