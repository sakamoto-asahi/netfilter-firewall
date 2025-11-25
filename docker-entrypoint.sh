#!/bin/bash
set -e

# nftablesの設定を適用
nft -f /etc/nftables.conf

exec "$@"