-- V4 RCE 复现种子：安装完成后导入。模拟运营者开启了"文件本地化"并配置了带文件下载字段+发布模块的单页采集任务。
USE skycaiji;
REPLACE INTO sky_config(cname,ctype,dateline,data) VALUES ('download_file',2,1791388264,'a:5:{s:13:\"download_file\";i:1;s:9:\"file_path\";s:0:\"\";s:8:\"file_url\";s:0:\"\";s:13:\"interval_file\";i:0;s:8:\"url_real\";i:0;}');
INSERT INTO sky_task(name,tg_id,module,auto,sort,addtime,caijitime,config) VALUES ('rce-single',0,'pattern',0,0,1791388264,0,'a:1:{s:6:\"single\";a:3:{s:4:\"open\";i:1;s:3:\"key\";s:0:\"\";s:6:\"always\";i:1;}}');
SET @tid := LAST_INSERT_ID();
INSERT INTO sky_collector(task_id,name,module,addtime,uptime,config) VALUES (@tid,'c1','pattern',1791388264,1791388264,'a:3:{s:10:\"field_list\";a:1:{i:0;a:2:{s:4:\"name\";s:7:\"content\";s:6:\"module\";s:6:\"dvalue\";}}s:13:\"field_process\";a:1:{i:0;a:1:{i:0;a:2:{s:6:\"module\";s:8:\"download\";s:11:\"download_op\";s:7:\"is_file\";}}}s:10:\"url_repeat\";i:1;}');
INSERT INTO sky_release(task_id,name,module,addtime,config) VALUES (@tid,'r1','datahub',1791388264,'a:0:{}');
SELECT @tid AS rce_task_id;
