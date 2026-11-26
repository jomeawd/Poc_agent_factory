FROM php:8.4.8-cli-alpine3.20
# Apply Alpine security updates at build time (base images lag behind the patched packages).
# hadolint ignore=DL3017
RUN apk upgrade --no-cache
RUN php -r 'foreach (["curl", "mbstring", "json"] as $ext) { if (!extension_loaded($ext)) { fwrite(STDERR, "Missing PHP extension: $ext\n"); exit(1); } }'
WORKDIR /app
COPY lib.php index.php ./
# Runs as root only to reach the Docker socket; this is the one service that has it.
ENV PHP_CLI_SERVER_WORKERS=4
CMD ["php", "-S", "0.0.0.0:8100", "index.php"]
