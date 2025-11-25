#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/file.h>
#include "firewall_io.h"

bool export_command(const char *src_file, const char *dst_file)
{
    char *err_msg = "エラー：予期せぬエラーが発生したため、"
                    "ルールのエクスポートを完了できませんでした。";
    char *tmp_file = NULL;
    FILE *src_fp = NULL;
    FILE *tmp_fp = NULL;
    int src_fd = -1;
    bool ret = false;

    // 引数チェック
    if (src_file == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    if (dst_file == NULL) {
        err_msg = "エラー：エクスポートするファイルを指定してください。";
        goto cleanup;
    }

    // ファイルのオープンとロック
    src_fp = fopen(src_file, "r");
    if (src_fp == NULL) {
        goto cleanup;
    }
    src_fd = fileno(src_fp);
    if (src_fd == -1) {
        goto cleanup;
    }
    if (flock(src_fd, LOCK_SH) == -1) {
        goto cleanup;
    }

    RuleCounts counts;
    if (get_rule_counts_from_file(src_fp, &counts) == false) {
        goto cleanup;
    }
    if (counts.total_count == 0) {
        err_msg = "エラー：ルールが存在しないため、"
                  "エクスポートが完了しませんでした。";
        goto cleanup;
    }

    // 一時ファイルの作成
    const char *suffix = ".tmp";
    size_t tmp_file_len = strlen(dst_file) + strlen(suffix) + 1;
    tmp_file = malloc(tmp_file_len);
    if (tmp_file == NULL) {
        goto cleanup;
    }
    snprintf(tmp_file, tmp_file_len, "%s%s", dst_file, suffix);
    tmp_fp = fopen(tmp_file, "w");
    if (tmp_fp == NULL) {
        goto cleanup;
    }

    if (copy_file(src_fp, tmp_fp) == false) {
        goto cleanup;
    }
    fclose(tmp_fp);
    tmp_fp = NULL;
    if (rename(tmp_file, dst_file) == -1) {
        goto cleanup;
    }
    printf("ルールのエクスポートが完了しました。\n");

    ret = true;

    cleanup:
    if (ret == false) {
        fprintf(stderr, "%s\n", err_msg);
    }
    if (src_fd != -1) {
        flock(src_fd, LOCK_UN);
    }
    if (src_fp != NULL) {
        fclose(src_fp);
    }
    if (tmp_fp != NULL) {
        fclose(tmp_fp);
    }
    if (tmp_file != NULL) {
        if (access(tmp_file, F_OK) == 0) {
            unlink(tmp_file);
        }
    }
    free(tmp_file);
    return ret;
}