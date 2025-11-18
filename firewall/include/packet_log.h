#ifndef PACKET_LOG_H
#define PACKET_LOG_H

#include <stdio.h>
#include "firewall_config.h"

void log_packet(
    FILE **log_fp,
    const unsigned char *packet,
    ChainType chain_type,
    FirewallRule *match_rule,
    ActionType policy,
    size_t logfile_rotate
);

#endif