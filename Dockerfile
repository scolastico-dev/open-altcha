FROM node:24-alpine AS base

WORKDIR /app
RUN npm install -g pnpm

FROM base AS builder

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install
COPY . .
RUN pnpm run build

FROM base

RUN apk add --no-cache curl espeak sox

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/docs ./docs
COPY demo.html ./
COPY LICENSE ./

EXPOSE 3000
CMD ["node", "dist/src/main"]
