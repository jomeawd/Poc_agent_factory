FROM node:24.1.0-alpine3.20 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json .
COPY src ./src
RUN npx tsc -p tsconfig.json && cp node_modules/qrcode-generator/qrcode.js dist/qrcode.js

# Unprivileged nginx: runs as uid 101 and listens on 8080, so the web container never needs root.
FROM nginxinc/nginx-unprivileged:1.27.3-alpine
# Apply Alpine security updates at build time (base images lag behind the patched packages).
USER root
# hadolint ignore=DL3017
RUN apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY public /usr/share/nginx/html
COPY --from=build /src/dist/ /usr/share/nginx/html/
USER 101
EXPOSE 8080
