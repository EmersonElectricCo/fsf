# This Docker image encapsulates the File Scanning Framework (FSF) by 
# Emerson Electric Company from https://github.com/EmersonElectricCo/fsf 
#
# To run this image after installing Docker using a standalone instance, use a command like 
# the following, replacing “~/fsf-workdir" with the path to the location of your FSF
# working directory:
#
# sudo docker run --rm -it -v ~/fsf-workdir:/home/nonroot/workdir wzod/fsf
#
# To run this image using a networked instance, use a command like this after installing
# FSF on the host system:
#
# sudo docker run --rm -it -p 5800:5800 -v ~/fsf-workdir:/home/nonroot/workdir wzod/fsf
#
# Before running FSF, create the  ~/fsf-workdir and make it world-accessible
# (“chmod a+xwr").
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM ubuntu:14.04
MAINTAINER Zod (@wzod)

ENV DEBIAN_FRONTEND noninteractive

USER root
RUN apt-get update && \
  apt-get -y install software-properties-common && \
  apt-add-repository -y multiverse && \
  apt-get -qq update && apt-get install -y --fix-missing \
  autoconf \
  automake \
  build-essential \
  cabextract \
  dh-autoreconf \
  git \
  jq \
  libffi-dev \
  libfuzzy-dev \
  libpython2.7-stdlib \
  libssl-dev \
  libtool \
  make \
  net-tools \
  python-dev \
  python-pip \
  python-setuptools \
  ssdeep \
  unrar \
  unzip \
  upx-ucl \
  vim \
  wget && \

# Update setuptools
  easy_install -U setuptools

# Retrieve current version of Yara via wget, verify known good hash and install Yara
RUN cd /tmp && \
  wget -O yarav3.4.0.tar.gz "https://github.com/plusvic/yara/archive/v3.4.0.tar.gz" && \
  echo 528571ff721364229f34f6d1ff0eedc3cd5a2a75bb94727dc6578c6efe3d618b\ \ yarav3.4.0.tar.gz > sha256sum-yara && \
  sha256sum -c sha256sum-yara && \

  tar vxzf yarav3.4.0.tar.gz && \
  cd yara-3.4.0 && \
  ./bootstrap.sh && \
  ./configure && \
  make && \
  make install && \

  cd yara-python/ && \
  python setup.py build && \
  python setup.py install && \
  cd /tmp && \

# Retrieve current version of pefile via wget, verify known good hash and install pefile
  wget -O pefile-1.2.10-139.tar.gz "http://pefile.googlecode.com/files/pefile-1.2.10-139.tar.gz" && \
  echo 8b7c5d853c97a923d0f6e128d0ae76b962aa75fd608d552f5a32e46276908a16\ \ pefile-1.2.10-139.tar.gz > sha256sum-pefile && \
  sha256sum -c sha256sum-pefile && \

  tar vxzf pefile-1.2.10-139.tar.gz && \
  cd pefile-1.2.10-139 && \
  python setup.py build && \
  python setup.py install && \
  cd /tmp && \

# Retrieve current version of jq via wget, verify known good hash and move to /usr/local/bin
  wget -O jq "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" && \
  echo c6b3a7d7d3e7b70c6f51b706a3b90bd01833846c54d32ca32f0027f00226ff6d\ \ jq > sha256sum-jq && \
  sha256sum -c sha256sum-jq && \
  chmod 755 jq && \
  mv jq /usr/local/bin/

# Install additional dependencies
RUN pip install czipfile \
  hachoir-parser \
  hachoir-core \
  hachoir-regex \
  hachoir-metadata \
  hachoir-subfile \
  ConcurrentLogHandler \
  pypdf2 \
  xmltodict \
  rarfile \
  pylzma \
  oletools \
  pyasn1_modules \ 
  pyasn1 \
  pyelftools \
  javatools \
  requests && \

  BUILD_LIB=1 pip install ssdeep

# Add nonroot user, clone repo and setup environment
RUN groupadd -r nonroot && \
  useradd -r -g nonroot -d /home/nonroot -s /sbin/nologin -c "Nonroot User" nonroot && \
  mkdir /home/nonroot && \
  chown -R nonroot:nonroot /home/nonroot && \
  echo "/usr/local/lib" >> /etc/ld.so.conf.d/yara.conf

USER nonroot
RUN mkdir -pv /home/nonroot/workdir && \
  cd /home/nonroot && \
  git clone https://github.com/EmersonElectricCo/fsf.git && \
  cd fsf/ && \
  sed -i 's/\/FULL\/PATH\/TO/\/home\/nonroot/' fsf-server/conf/config.py && \
  sed -i "/^SCANNER\_CONFIG/ s/\/tmp/\/home\/nonroot\/workdir/" fsf-server/conf/config.py 
  
USER root
RUN ldconfig && \
  ln -f -s /home/nonroot/fsf/fsf-server/main.py /usr/local/bin/ && \
  ln -f -s /home/nonroot/fsf/fsf-client/fsf_client.py /usr/local/bin/ && \
  apt-get remove -y --purge automake build-essential libtool && \
  apt-get autoremove -y --purge && \
  apt-get clean -y && \
  rm -rf /var/lib/apt/lists/*

USER nonroot
ENV HOME /home/nonroot
ENV USER nonroot
WORKDIR /home/nonroot/workdir

ENTRYPOINT sed -i "/^SERVER_CONFIG/ s/127\.0\.0\.1/$(hostname -i)/" /home/nonroot/fsf/fsf-client/conf/config.py && main.py start && printf "\n\n" && echo "<----->" && echo "FSF server daemonized!" &&  echo "<----->" && printf "\n" && echo "Invoke fsf_client.py by giving it a file as an argument:" && printf "\n" && echo "fsf_client.py <file>"  && printf "\n" && echo "Alternatively, Invoke fsf_client.py by giving it a file as an argument and pass to jq so you can interact extensively with the JSON output:" && printf "\n" && echo "fsf_client.py <file> | jq - C . | less -r" && printf "\n" && echo "To access all of the subobjects that are recursively processed, simply add --full when invoking fsf_client.py:" && printf "\n" && echo "fsf_client.py <file> --full" && printf "\n" && /bin/bash
