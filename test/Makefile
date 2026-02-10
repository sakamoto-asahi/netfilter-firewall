# プロジェクト設定
CC     := gcc
CFLAGS := -g -Wall -Iinclude

# 実行ファイル
TCP_SERVER := tcp_server
TCP_CLIENT := tcp_client
UDP_SERVER := udp_server
UDP_CLIENT := udp_client

# デフォルトターゲット
.PHONY: all clean
all: $(TCP_SERVER) $(TCP_CLIENT) $(UDP_SERVER) $(UDP_CLIENT)

# 実行ファイルの生成
$(TCP_SERVER):
	$(CC) $(CFLAGS) src/tcp_server.c src/test_utils.c -o $@

$(TCP_CLIENT):
	$(CC) $(CFLAGS) src/tcp_client.c src/test_utils.c -o $@

$(UDP_SERVER):
	$(CC) $(CFLAGS) src/udp_server.c src/test_utils.c -o $@

$(UDP_CLIENT):
	$(CC) $(CFLAGS) src/udp_client.c src/test_utils.c -o $@

clean:
	rm -f $(TCP_SERVER) $(TCP_CLIENT) $(UDP_SERVER) $(UDP_CLIENT)