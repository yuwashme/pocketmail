FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix dnsmasq-base dnsutils python3 && rm -rf /var/lib/apt/lists/*
COPY node.sh /node.sh
ENTRYPOINT ["/bin/sh","/node.sh"]
