# oven/bun with distrusted roots taken out of its built-in store (bun-distrust.ts)
# docker build -f docker/bun.Dockerfile --build-arg BUN_VERSION=1.4.3 -t ghcr.io/coinos/bun:1.4.3 docker/
ARG BUN_VERSION=1.4.3
FROM oven/bun:${BUN_VERSION}

COPY bun-distrust.ts /tmp/
RUN cp /usr/local/bin/bun /tmp/bun \
    && /tmp/bun /tmp/bun-distrust.ts /usr/local/bin/bun \
    && rm /tmp/bun /tmp/bun-distrust.ts
