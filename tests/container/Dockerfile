ARG VARNISH_VERSION=9.1
FROM varnish:${VARNISH_VERSION}
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      varnish-dev clang lld cmake ninja-build make \
      libssl-dev libjemalloc-dev python3 pkg-config git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
