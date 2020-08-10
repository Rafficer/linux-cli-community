FROM python:3.5

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qqy update
RUN apt-get -qqy upgrade
RUN apt-get -qqy install apt-utils

RUN apt-get -qqy install net-tools dnsutils
RUN apt-get -qqy install openvpn dialog python3-pip python3-setuptools

RUN pip install --upgrade pip
RUN pip install flake8

WORKDIR /linux-cli
ADD . /linux-cli/
RUN pip install -e .

CMD ["/bin/bash"]
