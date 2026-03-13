ARG PROJECT_NAME=raptor-gate_backend

FROM oven/bun:1 AS build
ARG PROJECT_NAME
ENV PROJECT_NAME=${PROJECT_NAME}
WORKDIR /usr/src/${PROJECT_NAME}

COPY backend/package.json backend/bun.lock ./
RUN bun install --frozen-lockfile

COPY backend/src ./src
COPY backend/tsconfig.json backend/tsconfig.build.json backend/nest-cli.json ./

RUN bun test
RUN bun run build

# Compile to a single standalone executable — no bun/node_modules needed at runtime
RUN bun build dist/main.js \
    --compile \
    --target=bun-linux-x64 \
    --outfile=/build/output/backend \
    --external=@nestjs/microservices \
    --external=@nestjs/websockets \
    --external=class-transformer \
    --external=class-validator

FROM alpine:3.19 AS runtime
COPY --from=build /build/output/backend /app/backend

CMD ["cp", "/app/backend", "/host/bin/backend"]
