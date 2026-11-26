FROM php:8.4.8-cli-alpine3.20
# Apply Alpine security updates at build time (base images lag behind the patched packages).
# hadolint ignore=DL3017,DL3018
RUN apk upgrade --no-cache \
 && apk add --no-cache libpq \
 && apk add --no-cache --virtual .build libpq-dev \
 && docker-php-ext-install pdo_pgsql \
 && apk del .build \
 && php -r 'foreach (["pdo_pgsql", "curl", "mbstring", "json"] as $ext) { if (!extension_loaded($ext)) { fwrite(STDERR, "Missing PHP extension: $ext\n"); exit(1); } }' \
 && adduser -D -u 10001 app
WORKDIR /app
COPY src ./src
COPY public ./public
USER app
ENV PHP_CLI_SERVER_WORKERS=8
CMD ["php", "-S", "0.0.0.0:8000", "-t", "public", "public/index.php"]
