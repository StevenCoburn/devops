# docker build -t meshcentral:1.1.11 --build-arg id=1000

FROM node:18.15.0-slim

ENV DEBIAN_FRONTEND="noninteractive"
ENV NODE_ENV="production"

RUN mkdir -p /opt/meshcentral

WORKDIR /opt/meshcentral

# Install packages for diagnostic use only
RUN apt-get update && \
  apt-get install -y curl wget dnsutils net-tools iputils-ping netcat && \
  rm -rf /var/lib/apt/lists/*

RUN npm install otplib@10.2.3 meshcentral archiver@5.3.2 ua-parser-js@1.0.35

ARG id
RUN groupadd -g ${id} mesh && \
  useradd -u ${id} -g ${id} -s /bin/bash mesh && \
  chown -R mesh:mesh /opt/meshcentral
USER mesh

EXPOSE 80 443 1100 4433 9971

VOLUME /opt/meshcentral/meshcentral-data
VOLUME /opt/meshcentral/meshcentral-files

CMD ["node","node_modules/meshcentral"]
