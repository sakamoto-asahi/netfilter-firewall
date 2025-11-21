#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include "stateful_inspection.h"
#include "firewall_config.h"

static StateUpdateResult update_tcp_state(
    StateTableEntry **head,
    StateTableEntry *entry_to_update,
    const unsigned char *packet
);

static StateUpdateResult update_icmp_state(
    StateTableEntry **head,
    StateTableEntry *entry_to_update,
    const unsigned char *packet
);

static bool is_matching_icmp_session(IcmpState *packet, IcmpState *entry);

bool is_state_tracking_required(const unsigned char *packet)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    size_t ip_hdr_len = ip_hdr->ihl * 4;

    if (ip_hdr->protocol == IPPROTO_TCP || ip_hdr->protocol == IPPROTO_UDP) {
        return true;
    }

    if (ip_hdr->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ip_hdr_len);
        uint8_t type = icmp_hdr->type;

        // ICMPは応答が必要なタイプだけトラッキングする
        if (type == ICMP_ECHO || type == ICMP_TIMESTAMP) {
            return true;
        }
    }

    return false;
}

bool init_state_entry(StateTableEntry **entry_out, const unsigned char *packet)
{
    StateTableEntry *entry = NULL;
    IcmpState *icmp_info = NULL;
    TcpState *tcp_info = NULL;
    UdpState *udp_info = NULL;
    bool ret = false;

    if (entry_out == NULL || packet == NULL) {
        errno = EINVAL;
        goto cleanup;
    }

    entry = malloc(sizeof(StateTableEntry));
    if (entry == NULL) {
        goto cleanup;
    }

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    entry->protocol = ip_hdr->protocol;
    entry->src_ip = ip_hdr->saddr;
    entry->dst_ip = ip_hdr->daddr;
    entry->last_activity = time(NULL);
    entry->next = NULL;
    entry->prev = NULL;

    switch (entry->protocol) {
        case IPPROTO_ICMP:
            struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ip_hdr_len);
            icmp_info = malloc(sizeof(IcmpState));
            if (icmp_info == NULL) {
                goto cleanup;
            }
            icmp_info->type = icmp_hdr->type;
            icmp_info->id = icmp_hdr->un.echo.id;
            icmp_info->sequence = icmp_hdr->un.echo.sequence;
            entry->proto_info = icmp_info;
            break;
        case IPPROTO_TCP:
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_hdr_len);
            tcp_info = malloc(sizeof(TcpState));
            if (tcp_info == NULL) {
                goto cleanup;
            }
            tcp_info->src_port = tcp_hdr->th_sport;
            tcp_info->dst_port = tcp_hdr->th_dport;
            tcp_info->fwd_fin = 0;
            tcp_info->rcv_fin = 0;
            entry->proto_info = tcp_info;
            break;
        case IPPROTO_UDP:
            struct udphdr *udp_hdr = (struct udphdr *)(packet + ip_hdr_len);
            udp_info = malloc(sizeof(UdpState));
            if (udp_info == NULL) {
                goto cleanup;
            }
            udp_info->src_port = udp_hdr->uh_sport;
            udp_info->dst_port = udp_hdr->uh_dport;
            entry->proto_info = udp_info;
            break;
        default:
            goto cleanup;
            break; // NOT REACHED
    }

    ret = true;

    cleanup:
    if (ret == true) {
        *entry_out = entry;
    } else {
        free(icmp_info);
        free(tcp_info);
        free(udp_info);
        free(entry);
        *entry_out = NULL;
    }
    return ret;
}

bool insert_state_entry(StateTableEntry **head, const unsigned char *packet)
{
    if (head == NULL || packet == NULL) {
        errno = EINVAL;
        return false;
    }

    if (*head != NULL) {
        // 同じエントリーがあれば、最終アクティブ時間を更新して終了
        StateTableEntry *existing_entry = lookup_state_table(*head, packet);
        if (existing_entry != NULL) {
            existing_entry->last_activity = time(NULL);
            return true;
        }
    }

    StateTableEntry *new_entry = NULL;
    if (init_state_entry(&new_entry, packet) == false) {
        return false;
    }

    if (*head != NULL) {
        (*head)->prev = new_entry;
    }
    new_entry->next = *head;
    *head = new_entry;

    return true;
}

void delete_entry(StateTableEntry **head, StateTableEntry *entry_to_delete)
{
    if (entry_to_delete == NULL) {
        errno = EINVAL;
        return;
    }

    if (entry_to_delete->prev == NULL) { // 削除対象が先頭の場合
        *head = entry_to_delete->next;
        if (*head != NULL) {
            (*head)->prev = NULL;
        }
    } else if (entry_to_delete->next == NULL) { // 削除対象が末尾の場合
        entry_to_delete->prev->next = NULL;
    } else {
        entry_to_delete->prev->next = entry_to_delete->next;
        entry_to_delete->next->prev = entry_to_delete->prev;
    }

    free(entry_to_delete->proto_info);
    free(entry_to_delete);
}

bool check_entry_timeout(
    StateTableEntry *entry_to_check,
    StateTimeouts state_timeouts
)
{
    if (entry_to_check == NULL) {
        errno = EINVAL;
        return false;
    }

    int timeout_sec;
    switch (entry_to_check->protocol) {
        case IPPROTO_ICMP:
            timeout_sec = state_timeouts.icmp_timeout_sec;
            break;
        case IPPROTO_TCP:
            timeout_sec = state_timeouts.tcp_timeout_sec;
            break;
        case IPPROTO_UDP:
            timeout_sec = state_timeouts.udp_timeout_sec;
            break;
        default:
            return false;
            break; // NOT REACHED
    }

    if (time(NULL) - entry_to_check->last_activity > timeout_sec) {
        return true;
    } else {
        return false;
    }
}

StateTableEntry *lookup_state_table(
    StateTableEntry *head,
    const unsigned char *packet
)
{
    if (head == NULL || packet == NULL) {
        errno = EINVAL;
        return NULL;
    }

    StateTableEntry *target_entry = NULL;
    if (init_state_entry(&target_entry, packet) == false) {
        return NULL;
    }

    StateTableEntry *current_entry = head;
    while (current_entry != NULL) {
        if (target_entry->protocol != current_entry->protocol) {
            current_entry = current_entry->next;
            continue;
        }

        // IPアドレスの順方向/逆方向のいずれかが一致するか確認
        bool ip_match_fwd = (
            target_entry->src_ip == current_entry->src_ip &&
            target_entry->dst_ip == current_entry->dst_ip
        );
        bool ip_match_rev = (
            target_entry->src_ip == current_entry->dst_ip &&
            target_entry->dst_ip == current_entry->src_ip
        );
        if (ip_match_fwd == false && ip_match_rev == false) {
            current_entry = current_entry->next;
            continue;
        }

        switch (target_entry->protocol) {
            case IPPROTO_ICMP:
                IcmpState *target_icmp = target_entry->proto_info;
                IcmpState *current_icmp = current_entry->proto_info;
                if (is_matching_icmp_session(target_icmp, current_icmp) == false) {
                    current_entry = current_entry->next;
                    continue;
                }
                break;
            case IPPROTO_TCP:
                TcpState *target_tcp = target_entry->proto_info;
                TcpState *current_tcp = current_entry->proto_info;
                bool tport_match_fwd = (
                    target_tcp->src_port == current_tcp->src_port &&
                    target_tcp->dst_port == current_tcp->dst_port
                );
                bool tport_match_rev = (
                    target_tcp->src_port == current_tcp->dst_port &&
                    target_tcp->dst_port == current_tcp->src_port
                );
                if (tport_match_fwd == false && tport_match_rev == false) {
                    current_entry = current_entry->next;
                    continue;
                }
                break;
            case IPPROTO_UDP:
                UdpState *target_udp = target_entry->proto_info;
                UdpState *current_udp = current_entry->proto_info;
                bool uport_match_fwd = (
                    target_udp->src_port == current_udp->src_port &&
                    target_udp->dst_port == current_udp->dst_port
                );
                bool uport_match_rev = (
                    target_udp->src_port == current_udp->dst_port &&
                    target_udp->dst_port == current_udp->src_port
                );
                if (uport_match_fwd == false && uport_match_rev == false) {
                    current_entry = current_entry->next;
                    continue;
                }
                break;
            default:
                break;
        }

        free(target_entry->proto_info);
        free(target_entry);
        return current_entry;
    }

    free(target_entry->proto_info);
    free(target_entry);
    return NULL;
}

void cleanup_expired_entries(StateTableEntry **head, StateTimeouts state_timeouts)
{
    StateTableEntry *current_entry = *head;
    while (current_entry != NULL) {
        StateTableEntry *next_entry = current_entry->next;
        if (check_entry_timeout(current_entry, state_timeouts) == true) {
            delete_entry(head, current_entry);
        }
        current_entry = next_entry;
    }
}

void destroy_state_table(StateTableEntry **head)
{
    if (head == NULL || *head == NULL) {
        return;
    }

    StateTableEntry *current_entry = *head;
    while (current_entry != NULL) {
        StateTableEntry *tmp_entry = current_entry->next;
        free(current_entry->proto_info);
        free(current_entry);
        current_entry = tmp_entry;
    }
    *head = NULL;
}

StateUpdateResult track_connection_state(
    StateTableEntry **head,
    StateTableEntry *entry_to_update,
    const unsigned char *packet,
    StateTimeouts state_timeouts
)
{
    if (check_entry_timeout(entry_to_update, state_timeouts) == true) {
        delete_entry(head, entry_to_update);
        return STATE_TIMED_OUT;
    }

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    switch (ip_hdr->protocol) {
        case IPPROTO_ICMP:
            return update_icmp_state(head, entry_to_update, packet);
            break; // NOT REACHED
        case IPPROTO_TCP:
            return update_tcp_state(head, entry_to_update, packet);
            break; // NOT REACHED
        case IPPROTO_UDP:
            entry_to_update->last_activity = time(NULL);
            return STATE_UPDATED;
            break; // NOT REACHED
        default:
            delete_entry(head, entry_to_update);
            return STATE_TERMINATED;
            break; // NOT REACHED
    }
}

static StateUpdateResult update_tcp_state(
    StateTableEntry **head,
    StateTableEntry *entry_to_update,
    const unsigned char *packet
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_hdr_len);
    TcpState *tcp_info = entry_to_update->proto_info;

    // RSTフラグ（強制終了）を検知
    if (tcp_hdr->rst == 1) {
        delete_entry(head, entry_to_update);
        return STATE_TERMINATED;
    }

    // FINフラグがすべて立っている状態で、ACKフラグを検知した場合、
    // TCPの接続が切断されたと見なし、エントリーを削除する
    if (tcp_hdr->ack == 1) {
        if (tcp_info->fwd_fin == 1 && tcp_info->rcv_fin == 1) {
            delete_entry(head, entry_to_update);
            return STATE_TERMINATED;
        }
    }

    // FINフラグを記録
    if (tcp_hdr->fin == 1) {
        if (entry_to_update->src_ip == ip_hdr->saddr) {
            // 順方向のパケットでFINフラグを検知
            tcp_info->fwd_fin = 1;
        } else {
            // 逆方向のパケットでFINフラグを検知
            tcp_info->rcv_fin = 1;
        }
    }

    // 最終アクティブ時間を更新して接続維持
    entry_to_update->last_activity = time(NULL);
    return STATE_UPDATED;
}

static StateUpdateResult update_icmp_state(
    StateTableEntry **head,
    StateTableEntry *entry_to_update,
    const unsigned char *packet
)
{
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ip_hdr_len);
    IcmpState *icmp_info = entry_to_update->proto_info;
    uint16_t packet_sequence = ntohs(icmp_hdr->un.echo.sequence);
    uint16_t entry_sequence = ntohs(icmp_info->sequence);

    if (icmp_info->type == icmp_hdr->type) {
        icmp_info->sequence = icmp_hdr->un.echo.sequence;
        entry_to_update->last_activity = time(NULL);
        return STATE_UPDATED;
    } else {
        if (packet_sequence < entry_sequence) {
            // パケットのシーケンス番号がエントリーよりも低い場合、
            // 遅延している可能性があるためエントリーは削除しない
            entry_to_update->last_activity = time(NULL);
            return STATE_UPDATED;
        } else {
            // 要求に対する応答の場合、エントリーは削除
            delete_entry(head, entry_to_update);
            return STATE_TERMINATED;
        }
    }
}

static bool is_matching_icmp_session(IcmpState *packet, IcmpState *entry)
{
    bool is_type_match = (packet->type == entry->type);
    bool is_type_pair = (
        (entry->type == ICMP_ECHO && packet->type == ICMP_ECHOREPLY) ||
        (entry->type == ICMP_TIMESTAMP && packet->type == ICMP_TIMESTAMPREPLY)
    );

    if (is_type_match == false && is_type_pair == false) {
        return false;
    }

    if (packet->id != entry->id) {
        return false;
    }

    return true;
}