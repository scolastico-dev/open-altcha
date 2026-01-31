FROM node:25-alpine AS base

WORKDIR /app
RUN npm install -g pnpm

FROM base AS builder

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build

FROM base

RUN apk add --no-cache curl espeak sox

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile
COPY --from=builder /app/dist ./dist
COPY demo.html ./

EXPOSE 3000
CMD ["node", "dist/src/main"]
