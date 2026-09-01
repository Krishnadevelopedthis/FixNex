# ---------------------------------------------------------------------------
# PR-CAMPUS frontend — built with Vite, served by nginx which also proxies
# /api (and the scan-progress WebSocket) through to the backend.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
