# syntax=docker/dockerfile:1
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
ARG SOURCE_REVISION=uncommitted
LABEL org.opencontainers.image.title="CrowdSec Traefik local plugin" \
      org.opencontainers.image.revision=$SOURCE_REVISION
WORKDIR /artifact
COPY bouncer.go version.go go.mod go.sum LICENSE .traefik.yml ban.html captcha.html ./
COPY pkg ./pkg
COPY vendor ./vendor
COPY patches ./patches
RUN find . -name '*_test.go' -delete && \
    find . -type f | sort | xargs sha256sum > /manifest.sha256 && \
    chmod -R a+rX /artifact
COPY packaging/install.sh /install.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh", "/install.sh"]
