#ifndef FIREWALL_CONFIG_H
#define FIREWALL_CONFIG_H

#include <stdbool.h>
#include <limits.h>
#include <netinet/ip.h>
#include "stateful_inspection.h"

// 各ファイルのパスの定義
#define APP_DIR "/app/" // プログラムの保存場所
#define FIREWALL_CONFIG_DIR APP_DIR "config/"
#define LOG_DIR APP_DIR "log/"
#define FIREWALL_CONFIG_FILE APP_DIR "config/firewall.conf"
#define TMP_FIREWALL_CONFIG_FILE APP_DIR "config/firewall.tmp"
#define RULE_FILE APP_DIR "config/rules.csv"
#define TMP_RULE_FILE APP_DIR "config/rules.tmp"
#define LOG_FILE APP_DIR "log/packet.log"
#define DOMAIN_SOCKET_PATH "/var/run/netfilter_firewall/firewall.sock"

#define LOG_FILE_MAX_LEN 256
#define CHAIN_MAX_LEN 8
#define PROTOCOL_MAX_LEN 8
#define IP_ADDR_MAX_LEN INET_ADDRSTRLEN
#define PORT_MAX_LEN 8
#define ADDR_PORT_MAX_LEN IP_ADDR_MAX_LEN + PORT_MAX_LEN
#define ACTION_MAX_LEN 8
#define LOG_STATUS_MAX_LEN 8
#define RULE_STATE_MAX_LEN 16
#define RULE_MAX_LEN 128
#define CONFIG_MAX_LEN 128

typedef enum {
    CONFIG_INPUT_POLICY,
    CONFIG_OUTPUT_POLICY,
    CONFIG_DEFAULT_LOGGING,
    CONFIG_LOGFILE_ROTATE,
    CONFIG_LOG_ROTATION_SIZE,
    CONFIG_ICMP_TIMEOUT_SEC,
    CONFIG_TCP_TIMEOUT_SEC,
    CONFIG_UDP_TIMEOUT_SEC,
    CONFIG_STATE_TABLE_CLEAN_INTERVAL,
    CONFIG_UNKNOWN
} ConfigType;

typedef enum {
    CHAIN_UNSPECIFIED,
    CHAIN_INPUT,
    CHAIN_OUTPUT
} ChainType;

typedef enum {
    PROTO_UNSPECIFIED,
    PROTO_ANY,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP
} ProtocolType;

typedef enum {
    ACTION_UNSPECIFIED,
    ACTION_ACCEPT,
    ACTION_DROP
} ActionType;

typedef enum {
    LOG_UNSPECIFIED,
    LOG_ENABLED,
    LOG_DISABLED
} LogStatus;

typedef enum {
    RULE_UNSPECIFIED,
    RULE_ENABLED,
    RULE_DISABLED
} RuleState;

typedef struct {
    ChainType chain;
    ProtocolType protocol;
    char src_ip[IP_ADDR_MAX_LEN];
    char dst_ip[IP_ADDR_MAX_LEN];
    int src_port; // -1はすべて許可
    int dst_port; // -1はすべて許可
    ActionType action;
    LogStatus log;
    RuleState state;
    char original[RULE_MAX_LEN];
} FirewallRule;

typedef struct {
    size_t input_count;
    size_t output_count;
    size_t total_count;
} RuleCounts;

typedef struct {
    ActionType input_policy;
    ActionType output_policy;
} FirewallPolicy;

typedef struct {
    ActionType input_policy;
    ActionType output_policy;
    LogStatus default_logging;
    size_t logfile_rotate;
    size_t log_rotation_size;
    StateTimeouts state_timeouts;
    size_t state_table_clean_interval;
} FirewallConfig;

// 設定のデフォルト値
extern const ActionType DEFAULT_POLICY;
extern const LogStatus DEFAULT_LOGGING; // ルールに一致しなかったパケットのログ設定
#define DEFAULT_LOGFILE_ROTATE 3
#define DEFAULT_LOG_ROTATION_SIZE_MB 10
#define DEFAULT_ICMP_CONNECTION_TIMEOUT_SEC 10
#define DEFAULT_TCP_CONNECTION_TIMEOUT_SEC 300
#define DEFAULT_UDP_CONNECTION_TIMEOUT_SEC 60
#define DEFAULT_STATE_TABLE_CLEAN_INTERVAL_SEC 30

// ルールのデフォルト値
extern const ProtocolType DEFAULT_PROTOCOL;
extern const char *DEFAULT_IP_ADDR;
extern const int DEFAULT_PORT;
extern const ActionType DEFAULT_ACTION;
extern const LogStatus DEFAULT_LOG_STATUS; // ルールに設定するデフォルトのログ
extern const RuleState DEFAULT_RULE_STATE;

// ルールの未設定の値
#define IP_ADDR_UNSPECIFIED ""
#define PORT_UNSPECIFIED INT_MIN
#define ORIGINAL_UNSPECIFIED ""

#endif