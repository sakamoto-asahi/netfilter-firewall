#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "firewall_config.h"
#include "stateful_inspection.h"

#define NFQ_HANDLER_TIMEOUT_SEC 1
#define CMD_LISTENER_TIMEOUT_SEC 1

typedef struct {
    struct nfq_handle *h;
} NfqHandlerArgs;

typedef struct {
    pthread_rwlock_t *rwlock;
    StateTableEntry **head;
    StateTimeouts *state_timeouts;
    size_t *clean_interval;
} StateTableCleanerArgs;

typedef struct {
    pthread_rwlock_t *rwlock;
    int domain_sock;
    char *config_file;
    char *rule_file;
    FirewallConfig *config;
    FirewallRule **input_rules;
    FirewallRule **output_rules;
    RuleCounts *rule_counts;
} CmdListenerArgs;

void *nfq_handler_thread(void *arg);
void *state_table_cleaner_thread(void *arg);
void *command_listener_thread(void *arg);

#endif