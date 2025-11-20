#ifndef STATEFUL_INSPECTION_H
#define STATEFUL_INSPECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

typedef struct {
    size_t icmp_timeout_sec;
    size_t tcp_timeout_sec;
    size_t udp_timeout_sec;
} StateTimeouts;

typedef struct StateTableEntry {
    uint8_t protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    void *proto_info;
    time_t last_activity;
    struct StateTableEntry *next;
    struct StateTableEntry *prev;
} StateTableEntry;

typedef struct {
    uint8_t type;
    uint16_t id;
    uint16_t sequence;
} IcmpState;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t fwd_fin:1;
    uint16_t rcv_fin:1;
} TcpState;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} UdpState;

typedef enum {
    STATE_UPDATED,
    STATE_TERMINATED,
    STATE_TIMED_OUT
} StateUpdateResult;

bool is_state_tracking_required(const unsigned char *packet);
bool init_state_entry(StateTableEntry **entry_out, const unsigned char *packet);
bool insert_state_entry(StateTableEntry **head, const unsigned char *packet);
void delete_entry(StateTableEntry **head, StateTableEntry *entry_to_delete);
bool check_entry_timeout(StateTableEntry *entry_to_check, StateTimeouts state_timeouts);
StateTableEntry *lookup_state_table(StateTableEntry *head, const unsigned char *packet);
void cleanup_expired_entries(StateTableEntry **head, StateTimeouts state_timeouts);
void destroy_state_table(StateTableEntry **head);
StateUpdateResult track_connection_state(
    StateTableEntry **head,
    StateTableEntry *entry_to_update,
    const unsigned char *packet,
    StateTimeouts state_timeouts
);

#endif