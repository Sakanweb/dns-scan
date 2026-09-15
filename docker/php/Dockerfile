FROM yiisoftware/yii-php:8.4-fpm

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-dnsutils \
        curl \
        git \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
