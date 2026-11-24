# One image, two roles (lowside | highside). Node >= 23.6 runs TypeScript natively
# via type stripping, so the container ships source with no build step and no
# runtime npm dependencies, which suits air-gapped image import.
FROM node:24-alpine AS base
RUN addgroup -S tollgate && adduser -S -G tollgate -u 10001 tollgate
WORKDIR /app
COPY core ./core
COPY services ./services
COPY policy ./policy
COPY package.json ./
USER 10001
ENV TG_DATA=/data TG_KEYS=/keys NODE_ENV=production
VOLUME ["/data"]
ENTRYPOINT ["node"]
CMD ["services/lowside.ts"]
