#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stdio.h>
#include <pthread.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "firewall_config.h"
#include "stateful_inspection.h"

typedef struct {
    pthread_rwlock_t *rwlock;
    StateTableEntry **head;
    FirewallRule **fw_rules;
    size_t *fw_rule_count;
    FILE **log_fp;
    FirewallConfig *config;
} PacketHandlerArgs;

int handle_input_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
);

int handle_output_packet(
    struct nfq_q_handle *qh,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa,
    void *data
);

#endif