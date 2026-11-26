FROM alpine:3.24.4
# Apply Alpine security updates at build time (base images lag behind the patched packages).
# hadolint ignore=DL3017,DL3018
RUN apk upgrade --no-cache && apk add --no-cache tinyproxy
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY allowlist /etc/tinyproxy/allowlist
USER tinyproxy
EXPOSE 8888
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
