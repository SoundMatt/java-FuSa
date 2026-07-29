# syntax=docker/dockerfile:1.4
# ── Build stage ───────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS builder

LABEL io.x-fusa.stage="build"

WORKDIR /build

# Cache dependencies before copying source
COPY pom.xml .
RUN mvn -q dependency:go-offline -B

COPY src ./src
RUN mvn -q package -DskipTests -B

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine AS runtime

ARG VERSION=0.6.2
ARG SPEC_VERSION=1.15.2
ARG BUILD_DATE
ARG GIT_COMMIT=unknown

LABEL org.opencontainers.image.title="jfusa" \
      org.opencontainers.image.description="Java Functional Safety Tool Suite — x-FuSa spec v${SPEC_VERSION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.vendor="SoundMatt" \
      io.x-fusa.tool="jfusa" \
      io.x-fusa.language="java" \
      io.x-fusa.spec-version="${SPEC_VERSION}"

# Non-root user for security
RUN addgroup -S jfusa && adduser -S jfusa -G jfusa

WORKDIR /project

COPY --from=builder /build/target/jfusa.jar /usr/local/lib/jfusa.jar

# Wrapper script so ENTRYPOINT forwards all arguments
RUN printf '#!/bin/sh\nexec java -jar /usr/local/lib/jfusa.jar "$@"\n' \
      > /usr/local/bin/jfusa && chmod +x /usr/local/bin/jfusa

USER jfusa

ENTRYPOINT ["/usr/local/bin/jfusa"]
CMD ["--help"]

# Health probe — check version
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD jfusa version || exit 1
