FROM vulhub/php:5.6-apache

LABEL maintainer="phithon <root@leavesongs.com>"

COPY www/* /var/www/html/

RUN echo 'deb http://mirrors.tencent.com/debian-archive/debian jessie main' > /etc/apt/sources.list
RUN echo 'deb http://mirrors.tencent.com/debian-archive/debian-security jessie/updates main' >> /etc/apt/sources.list

RUN set -ex \
    && apt-get update \
    && apt-get install -y --force-yes --no-install-recommends git \
    && cd /var/www/html/ \
    && curl -sSL https://getcomposer.org/installer | php \
    && php composer.phar install \
    && rm -rf /var/lib/apt/lists/*