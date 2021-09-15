# TO BUILD
# on host system
# first clone the fsf repo to ScannerDeployment/fsf/
# build command from ScannerDeployment/fsf/ directory
# docker build -t fsf-server .
# TO RUN
# docker run -d -p 5800:5800 --restart=always --rm=true -v /data/yara:/data/yara -v /var/log/scanner:/var/log/scanner -v /data/file_extract/:/data/file_extract --name fsf-server fsf-server
FROM centos:7
RUN yum update -y && yum upgrade -y
RUN yum install -y epel-release
RUN yum install -y \
    wget \
    openssl \
    openssl-devel \
    vim-enhanced \
    ntp \
    openldap-clients \
    make \
    cmake \
    ntpdate \
    lsof \
    mlocate \
    htop \
    net-tools \
    bc \
    tree \
    policycoreutils-python \
    parted \
    git \
    zlib \
    zlib-devel \
    gcc \
    flex \
    bison \
    pcre \
    pcre-devel \
    libdnet \
    libdnet-devel \
    policycoreuti \
    bridge-utils \
    libpcap \
    libpcap-devel \
    numactl-devel \
    python-argpar \
    python-devel \
    python-pip \
    ssdeep-devel \
    libffi-devel \
#    unrar \
    cabextract \
    python-setuptools \
    jq \
    flex \
    bison \
    make \
    cmake \
    automake \
    libtool \
    openssl \
    openssl-devel
WORKDIR /tmp
RUN wget https://www.rarlab.com/rar/rarlinux-x64-5.5.0.tar.gz && \
    tar -zxvf rarlinux-x64-5.5.0.tar.gz && \
    cd rar && \
    cp -v rar unrar /usr/local/bin/
RUN pip install --upgrade pip
RUN pip install --upgrade setuptools
RUN pip install \
    czipfile \
    hachoir-parser \
    hachoir-core \
    hachoir-regex \
    hachoir-metadata \
    hachoir-subfile \
    ConcurrentLogHandler \
    pypdf2 \
    xmltodict \
    rarfile \
    ssdeep \
    pylzma \
    oletools \
    pyasn1-modules \
    pyasn1 \
    pycrypto \
    pyopenssl \
    ndg-httpsclient \
    pyelftools \
    javatools \
    requests \
    future \
    pefile \
    git+https://github.com/aaronst/macholibre.git \
    python-bencode \
    uncompyle2 \
    pdfminer \
    beautifulsoup4 \
    python-magic \
    openxmllib
RUN pip install androguard
RUN pip install ConcurrentLogHandler
RUN rpm -Uvh ftp://ftp.pbone.net/mirror/download.fedora.redhat.com/pub/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/f/file-libs-5.37-2.fc31.x86_64.rpm && rpm -Uvh ftp://ftp.pbone.net/mirror/download.fedora.redhat.com/pub/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/f/file-devel-5.37-2.fc31.x86_64.rpm
WORKDIR /tmp/
RUN wget -O yara.tar.gz https://github.com/VirusTotal/yara/archive/v3.4.0.tar.gz && \
    tar vxzf yara.tar.gz && \
    cd yara-3.4.0 && \
    ./bootstrap.sh && \
    ./configure --enable-magic --with-crypto --enable-dotnet && \
    make && \
    make install && echo /usr/local/lib >> /etc/ld.so.conf && ldconfig && \
    cd /tmp/yara-3.4.0/yara-python && python setup.py build && python setup.py install
WORKDIR /data/
RUN mkdir /data/file_extract
RUN mkdir /data/yara_repo/
RUN mkdir /var/log/scanner
# copy fsf folder to /data/fsf
ADD Docker /data/
CMD python /data/fsf-server/fsf_foreground.py