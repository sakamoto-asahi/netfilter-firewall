#include <stdio.h>
#include <stdbool.h>
#include "firewall_config.h"
#include "domain_socket_utils.h"

bool reload_config_command(void)
{
    ServerResponse response = send_command_to_server(
        DOMAIN_SOCKET_PATH,
        CMD_RELOAD_CONFIG
    );
    switch (response) {
        case RES_SUCCESS:
            printf("設定を再読み込みしました。\n");
            break;
        case RES_FAILURE:
            fprintf(stderr, "エラー：ファイアウォールが設定の再読み込みに失敗しました。\n");
            return false;
            break; // NOT REACHED
        case RES_TIMEOUT:
            fprintf(stderr, "エラー：ファイアウォールからの応答がタイムアウトしました。\n");
            return false;
            break; // NOT REACHED
        case RES_ERROR:
            fprintf(stderr, "エラー：ファイアウォールへの接続に失敗しました。\n");
            return false;
            break; // NOT REACHED
        default:
            fprintf(stderr, "エラー：予期せぬエラーが発生したため、設定の再読み込みに失敗しました。\n");
            return false;
            break; // NOT REACHED
    }

    return true;
}