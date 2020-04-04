FROM python:3.7-stretch

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

COPY frozen_requirements.txt ./
RUN pip --no-cache-dir install -r frozen_requirements.txt \
    && apt-get update \
    #
    # Install Shell Check
    && apt-get install -y shellcheck \
    #
    # Install openvpn
    apt-get install --no-install-recommends -y openvpn dialog  2>&1 \
    #
    # Install Docker CE CLI
    && apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common lsb-release \
    && curl -fsSL https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg | apt-key add - 2>/dev/null \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]') $(lsb_release -cs) stable" \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    #
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*