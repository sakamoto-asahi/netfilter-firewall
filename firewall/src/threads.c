#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "threads.h"
#include "nfq_config.h"
#include "firewall_io.h"
#include "domain_socket_utils.h"
#include "stateful_inspection.h"

extern sig_atomic_t termination_flag;

void *nfq_handler_thread(void *arg)
{
    NfqHandlerArgs *args = (NfqHandlerArgs *)arg;
    struct nfq_handle *h = args->h;
    int fd = nfq_fd(args->h);
    char buf[PACKET_BUFFER_SIZE] __attribute__ ((aligned));

    // タイムアウト設定
    struct timeval timeout;
    timeout.tv_sec = NFQ_HANDLER_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (termination_flag == 0) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len >= 0) {
            nfq_handle_packet(h, buf, len);
        }
    }

    return NULL;
}

void *state_table_cleaner_thread(void *arg)
{
    StateTableCleanerArgs *args = (StateTableCleanerArgs *)arg;
    pthread_rwlock_t *rwlock = args->rwlock;
    StateTableEntry **head = args->head;
    StateTimeouts *state_timeouts = args->state_timeouts;

    while (1) {
        for (int i = 0; i < STATE_TABLE_CLEANER_INTERVAL_SEC; i++) {
            if (termination_flag == 1) {
                return NULL;
            }
            sleep(1);
        }
        pthread_rwlock_wrlock(rwlock);
        cleanup_expired_entries(head, *state_timeouts);
        pthread_rwlock_unlock(rwlock);
    }
}

void *command_listener_thread(void *arg)
{
    CmdListenerArgs *args = (CmdListenerArgs *)arg;
    pthread_rwlock_t *rwlock = args->rwlock;
    int domain_sock = args->domain_sock;
    char *config_file = args->config_file;
    char *rule_file = args->rule_file;
    FirewallConfig *config = args->config;
    FirewallRule **input_rules = args->input_rules;
    FirewallRule **output_rules = args->output_rules;
    RuleCounts *rule_counts = args->rule_counts;

    while (termination_flag == 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(domain_sock, &readfds);

        // タイムアウト設定
        struct timeval timeout;
        timeout.tv_sec = CMD_LISTENER_TIMEOUT_SEC;
        timeout.tv_usec = 0;

        int ret_select = select(domain_sock + 1, &readfds, NULL, NULL, &timeout);
        if (ret_select <= 0) { // エラーまたはタイムアウト
            continue;
        }

        if (FD_ISSET(domain_sock, &readfds)) {
            int client = accept(domain_sock, NULL, NULL);
            if (client == -1) {
                continue;
            }

            ServerCommand cmd;
            ssize_t n = recv(client, &cmd, sizeof(cmd), 0);
            if (n == -1) {
                close(client);
                continue;
            }

            ServerResponse res = RES_FAILURE;
            bool success = false;
            switch (cmd) {
                case CMD_RELOAD_RULES:
                    pthread_rwlock_wrlock(rwlock);
                    success = reload_rules(
                        rule_file, input_rules, output_rules, rule_counts
                    );
                    pthread_rwlock_unlock(rwlock);
                    if (success == true) {
                        res = RES_SUCCESS;
                    }
                    break;
                case CMD_RELOAD_CONFIG:
                    pthread_rwlock_wrlock(rwlock);
                    success = reload_config(
                        config_file, config
                    );
                    pthread_rwlock_unlock(rwlock);
                    if (success == true) {
                        res = RES_SUCCESS;
                    }
                    break;
                case CMD_SHUTDOWN:
                    termination_flag = 1;
                    res = RES_SUCCESS;
                    break;
                default:
                    break;
            }
            send(client, &res, sizeof(res), 0);
            close(client);
        }
    }

    return NULL;
}