<?php
/*
 * 模拟云厂商实例元数据服务（阿里云 100.100.100.200 / AWS 169.254.169.254 等）。
 * 真实环境中该地址只有服务器本机可访问，外部攻击者够不到；SSRF 的价值即在于借服务端去访问它。
 * 这里对任意路径返回一份伪造的 RAM/STS 临时访问凭证。
 */
$uri = $_SERVER['REQUEST_URI'];

// 演示“302 重定向跟随”——攻击者可用一个看似无害的外部 URL 跳转到内网元数据，绕过潜在的首跳 host 白名单
if (strpos($uri, '/redirect') === 0) {
    header('Location: http://metadata.internal/latest/meta-data/ram/security-credentials/myrole', true, 302);
    exit;
}

header('Content-Type: application/json');
// 均为明显占位值（非真实凭据、不匹配任何云厂商密钥格式），仅用于演示“泄漏了什么”
echo json_encode(array(
    "AccessKeyId"     => "EXAMPLE-STS-ACCESS-KEY-ID-PLACEHOLDER",
    "AccessKeySecret" => "EXAMPLE-STS-ACCESS-KEY-SECRET-PLACEHOLDER",
    "SecurityToken"   => "EXAMPLE-STS-SESSION-TOKEN-PLACEHOLDER",
    "Expiration"      => "2026-10-07T00:00:00Z",
    "Code"            => "Success",
    "LastUpdated"     => "2026-10-06T00:00:00Z",
));
