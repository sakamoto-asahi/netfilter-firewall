#ifndef FIREWALL_PARSER_H
#define FIREWALL_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "firewall_config.h"

ProtocolType get_protocol_from_number(uint8_t proto_num);
bool get_packet_ports(const unsigned char *packet, int *src_port, int *dst_port);
bool config_to_string(ConfigType config, char *str_out, size_t str_len);
bool rule_chain_to_string(ChainType chain, char *str_out, size_t str_len);
bool rule_protocol_to_string(ProtocolType proto, char *str_out, size_t str_len);
bool rule_port_to_string(int port, char *str_out, size_t str_len);
bool rule_action_to_string(ActionType action, char *str_out, size_t str_len);
bool rule_log_to_string(LogStatus log, char *str_out, size_t str_len);
bool rule_state_to_string(RuleState state, char *str_out, size_t str_len);
int parse_config_number(const char *config_number, int min_num);
ConfigType parse_config_string(const char *config_string);
ChainType parse_chain_string(const char *chain_str);
ProtocolType parse_protocol_string(const char *proto_str);
ActionType parse_action_string(const char *action_str);
LogStatus parse_log_string(const char *log_str);
RuleState parse_state_string(const char *state_str);
bool parse_rule_string(const char *str, FirewallRule *rule_out);
bool format_rule_string(const FirewallRule *rule, char *str_out, size_t str_len);

#endif