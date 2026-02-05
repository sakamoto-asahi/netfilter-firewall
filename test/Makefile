# プロジェクト設定
CC     := gcc
CFLAGS := -g -Wall -Iinclude

# 実行ファイル
UDP_SERVER := udp_server
UDP_CLIENT := udp_client

# デフォルトターゲット
.PHONY: all clean
all: $(UDP_SERVER) $(UDP_CLIENT)

# 実行ファイルの生成
$(UDP_SERVER):
	$(CC) $(CFLAGS) src/udp_server.c src/test_utils.c -o $@

$(UDP_CLIENT):
	$(CC) $(CFLAGS) src/udp_client.c src/test_utils.c -o $@

clean:
	rm -f $(UDP_SERVER) $(UDP_CLIENT)