# syntax=docker/dockerfile:1
FROM node:18-alpine AS base

WORKDIR /app

COPY package*.json ./

RUN npm ci --production

COPY app.js ./

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "app.js"]
