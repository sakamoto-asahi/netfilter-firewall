#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/file.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "nfq_config.h"
#include "firewall_config.h"
#include "firewall_init.h"
#include "firewall_io.h"
#include "nfq_config.h"
#include "nfq_utils.h"
#include "stateful_inspection.h"
#include "packet_handler.h"
#include "domain_socket_utils.h"
#include "threads.h"

volatile sig_atomic_t termination_flag = 0;

static void signal_handler(int sig) {
    termination_flag = 1;
}

int main(void)
{
    struct nfq_handle *h = NULL; // NFQUEUEと接続するハンドル
    struct nfq_q_handle *q_handles[Q_HANDLE_LEN] = {0}; // パケットを受信するハンドルの配列
    int nfq_sock = -1;
    int domain_sock = -1;
    StateTableEntry *head = NULL;
    FirewallRule *fw_input_rules = NULL;
    FirewallRule *fw_output_rules = NULL;
    pthread_rwlock_t *rwlock = NULL; // スレッドロック
    FILE *log_fp = NULL;
    int ret = 1;

    // シグナルハンドラの設定
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
        goto cleanup;
    }

    // 必要なファイルなどを作成
    if (init_env() == false) {
        goto cleanup;
    }

    // 設定の読み込み
    FirewallConfig config;
    if (reload_config(FIREWALL_CONFIG_FILE, &config) == false) {
        goto cleanup;
    }

    // ルールの読み込み
    RuleCounts fw_rule_counts;
    if (reload_rules(RULE_FILE, &fw_input_rules, &fw_output_rules,
                     &fw_rule_counts) == false) {
        goto cleanup;
    }

    // ログファイルを開く
    log_fp = fopen(LOG_FILE, "a");
    if (log_fp == NULL) {
        goto cleanup;
    }

    // スレッドロックの設定
    rwlock = malloc(sizeof(pthread_rwlock_t));
    if (rwlock == NULL) {
        goto cleanup;
    }
    if (pthread_rwlock_init(rwlock, NULL) != 0) {
        goto cleanup;
    }

    // NFQUEUEソケットの作成
    nfq_sock = create_nfq_socket(&h);
    if (nfq_sock == -1) {
        goto cleanup;
    }
    PacketHandlerArgs input_args = {
        rwlock,
        &head,
        &fw_input_rules,
        &fw_rule_counts.input_count,
        &log_fp,
        &config
    };
    PacketHandlerArgs output_args = {
        rwlock,
        &head,
        &fw_output_rules,
        &fw_rule_counts.output_count,
        &log_fp,
        &config
    };
    // INPUTチェインのパケットを受信するハンドルの作成
    for (int i = MIN_INPUT_QUEUE_NUMBER; i <= MAX_INPUT_QUEUE_NUMBER; i++) {
        q_handles[i] = create_nfq_queue_handle(
            h, i, &handle_input_packet, &input_args
        );
        if (q_handles[i] == NULL) {
            goto cleanup;
        }
    }
    // OUTPUTチェインのパケットを受信するハンドルの作成
    for (int i = MIN_OUTPUT_QUEUE_NUMBER; i <= MAX_OUTPUT_QUEUE_NUMBER; i++) {
        q_handles[i] = create_nfq_queue_handle(
            h, i, &handle_output_packet, &output_args
        );
        if (q_handles[i] == NULL) {
            goto cleanup;
        }
    }

    // UNIXドメインソケットの作成
    domain_sock = create_server_domain_socket(DOMAIN_SOCKET_PATH, 10);
    if (domain_sock == -1) {
        goto cleanup;
    }

    // スレッドに渡す引数を設定
    NfqHandlerArgs nfq_handler_args = {
        h
    };
    StateTableCleanerArgs state_table_cleaner_args= {
        rwlock,
        &head
    };
    CmdListenerArgs cmd_listener_args = {
        rwlock,
        domain_sock,
        FIREWALL_CONFIG_FILE,
        RULE_FILE,
        &config,
        &fw_input_rules,
        &fw_output_rules,
        &fw_rule_counts
    };

    // スレッドの作成
    pthread_t threads[THREAD_LEN];
    for (int i = 0; i < Q_HANDLE_LEN; i++) {
        if (pthread_create(&threads[i], NULL, nfq_handler_thread,
                           &nfq_handler_args) != 0) {
            goto cleanup;
        }
    }
    if (pthread_create(&threads[Q_HANDLE_LEN], NULL, state_table_cleaner_thread,
                       &state_table_cleaner_args) != 0) {
        goto cleanup;
    }
    if (pthread_create(&threads[Q_HANDLE_LEN + 1], NULL, command_listener_thread,
                       &cmd_listener_args) != 0) {
        goto cleanup;
    }

    // スレッドの終了を待機
    for (int i = 0; i < THREAD_LEN; i++) {
        pthread_join(threads[i], NULL);
    }

    ret = 0;

    cleanup:
    destroy_nfq_queues(q_handles, Q_HANDLE_LEN);
    if (h != NULL) {
        nfq_close(h);
    }
    if (nfq_sock != -1) {
        close(nfq_sock);
    }
    if (domain_sock != -1) {
        close(domain_sock);
        unlink(DOMAIN_SOCKET_PATH);
    }
    if (log_fp != NULL) {
        fclose(log_fp);
    }
    free(fw_input_rules);
    free(fw_output_rules);
    destroy_state_table(&head);
    free(rwlock);
    return ret;
}