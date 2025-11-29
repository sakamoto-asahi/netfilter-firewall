FROM ubuntu:24.04

ARG TZ=Asia/Tokyo
ARG APP_DIR=/app

# パッケージのインストール
RUN apt-get update && \
    apt-get install -y \
    nftables iproute2 iputils-ping curl \
    gcc make vim libnetfilter-queue-dev \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

# タイムゾーンの設定
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

# ソースコードをコンテナ内にコピー
COPY . $APP_DIR
COPY config/nftables.conf /etc/nftables.conf

# プログラムのコンパイル
WORKDIR $APP_DIR
RUN make

# 実行ファイルを実行パスにコピー
RUN cp $APP_DIR/build/fw /usr/local/bin/nfw
RUN cp $APP_DIR/build/fw_ctl /usr/local/bin/nfw-ctl

# エントリーポイントの設定
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["/bin/bash"]