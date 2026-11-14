#!/usr/bin/env bash
# 在 iSH 里执行：bash deploy.sh
# 只负责应用本身，不改 cloudflared（那一步单独做）
set -euo pipefail
HOST=${HOST:-vps}
DIR=/opt/115dl

ssh "$HOST" "mkdir -p $DIR"
scp -q app.py requirements.txt 115dl.service "$HOST:$DIR/"

ssh "$HOST" "cd $DIR && python3 -m venv venv && venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q -r requirements.txt"

if ! ssh "$HOST" "test -f $DIR/env"; then
  TOKEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  ssh "$HOST" "printf 'API_TOKEN=%s\n' '$TOKEN' > $DIR/env && chmod 600 $DIR/env"
else
  TOKEN=$(ssh "$HOST" "grep -oP '(?<=API_TOKEN=).*' $DIR/env")
fi

ssh "$HOST" "cp $DIR/115dl.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now 115dl && sleep 1 && systemctl is-active 115dl"

cat <<EOF

服务已启动：127.0.0.1:7875
API_TOKEN=$TOKEN

下一步（需要确认后执行）：
  在 /etc/cloudflared/config.yml 的 ingress 末尾加：
    - hostname: your-domain.example.com
      service: http://127.0.0.1:7875
  然后：
    cloudflared tunnel route dns <TUNNEL_ID> your-domain.example.com
    systemctl restart cloudflared
EOF
