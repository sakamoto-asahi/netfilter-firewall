FROM ubuntu:24.04

ENV TZ=Asia/Tokyo

# パッケージのインストール
RUN apt-get update && \
    apt-get install -y \
    nftables iproute2 iputils-ping curl \
    gcc make vim libnetfilter-queue-dev \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

# 日本時間に設定
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

# ソースコードをコンテナ内にコピー
COPY . /app
COPY config/nftables.conf /etc/nftables.conf

# プログラムのコンパイル
WORKDIR /app
RUN make

# エントリーポイントの設定
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/bin/bash"]