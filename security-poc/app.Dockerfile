# SkyCaiji 3.1 测试镜像 (PHP 7.4 + Apache)，仅供漏洞复现使用
FROM php:7.4-apache

RUN docker-php-ext-install pdo_mysql mysqli >/dev/null 2>&1 || true
RUN a2enmod rewrite >/dev/null 2>&1
RUN apt-get update >/dev/null 2>&1 \
 && apt-get install -y libpng-dev libjpeg-dev libfreetype6-dev default-mysql-client >/dev/null 2>&1 \
 && docker-php-ext-configure gd --with-freetype --with-jpeg >/dev/null 2>&1 \
 && docker-php-ext-install gd >/dev/null 2>&1 || true

RUN { \
      echo "error_reporting = E_ERROR"; \
      echo "display_errors = Off"; \
      echo "session.use_cookies = 1"; \
      echo "post_max_size = 64M"; \
      echo "upload_max_filesize = 64M"; \
    } > /usr/local/etc/php/conf.d/zz-skycaiji.ini

# 复制 SkyCaiji 源码（构建上下文为仓库根目录）
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html/data /var/www/html/runtime 2>/dev/null || true \
 && chmod -R 0777 /var/www/html/data /var/www/html/runtime 2>/dev/null || true \
 && rm -f /var/www/html/data/install.lock /var/www/html/data/config.php 2>/dev/null || true

WORKDIR /var/www/html
