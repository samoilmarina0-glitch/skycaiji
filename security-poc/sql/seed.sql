-- 由 security-poc 生成；SkyCaiji 安装完成后导入。以下均为明显占位值，非真实凭据。
USE skycaiji;
REPLACE INTO sky_config(cname,ctype,dateline,data) VALUES ('translate',2,1791324449,'a:3:{s:6:\"engine\";s:7:\"tencent\";s:7:\"tencent\";a:2:{s:8:\"secretid\";s:36:\"EXAMPLE-TENCENT-SECRETID-PLACEHOLDER\";s:9:\"secretkey\";s:37:\"EXAMPLE-TENCENT-SECRETKEY-PLACEHOLDER\";}s:5:\"baidu\";a:2:{s:5:\"appid\";s:17:\"20231015000900000\";s:3:\"key\";s:35:\"EXAMPLE-BAIDU-TRANS-KEY-PLACEHOLDER\";}}');
REPLACE INTO sky_config(cname,ctype,dateline,data) VALUES ('email',2,1791324449,'a:6:{s:4:\"type\";s:4:\"smtp\";s:6:\"server\";s:18:\"smtp.exmail.qq.com\";s:4:\"port\";i:465;s:7:\"account\";s:22:\"noreply@victim.example\";s:8:\"password\";s:33:\"EXAMPLE-SMTP-PASSWORD-PLACEHOLDER\";s:5:\"email\";s:22:\"noreply@victim.example\";}');
REPLACE INTO sky_config(cname,ctype,dateline,data) VALUES ('proxy',2,1791324449,'a:5:{s:4:\"open\";i:0;s:4:\"type\";s:4:\"http\";s:6:\"server\";s:13:\"10.0.0.9:8080\";s:4:\"user\";s:9:\"proxyuser\";s:3:\"pwd\";s:34:\"EXAMPLE-PROXY-PASSWORD-PLACEHOLDER\";}');
INSERT INTO sky_task(name,tg_id,module,auto,sort,addtime,caijitime,config) VALUES ('single-collect-api',0,'pattern',0,0,1791324449,0,'a:1:{s:6:\"single\";a:3:{s:4:\"open\";i:1;s:3:\"key\";s:0:\"\";s:6:\"always\";i:1;}}');
SET @tid := LAST_INSERT_ID();
INSERT INTO sky_collector(task_id,name,module,addtime,uptime,config) VALUES (@tid,'c1','pattern',1791324449,1791324449,'a:2:{s:10:\"field_list\";a:1:{i:0;a:2:{s:4:\"name\";s:7:\"content\";s:6:\"module\";s:6:\"dvalue\";}}s:10:\"url_repeat\";i:1;}');
SELECT @tid AS seeded_task_id;
