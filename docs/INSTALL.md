Install Guide
=============

The following step-by-step instructions were tested against Ubuntu Server 14.04.3 and CentOS 7.

Required Packages 
------------------

Install the following required packages. Once you complete this step, the rest of the installation is the same for either platform.

###Ubuntu###

```
sudo apt-get install autoconf dh-autoreconf python-dev libpython2.7-stdlib python-pip libffi-dev ssdeep upx unrar libfuzzy-dev unzip wget vim libssl-dev net-tools cabextract
```

###CentOS###

`sudo yum install autoconf python-devel automake wget vim libtool openssl openssl-devel net-tools cabextract`

Turn on EPEL repo.

`sudo yum install epel-release`

Turn on RPMForge repo.
```
wget http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
rpm -Uvh rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
```
Get remaining packages.

`sudo yum install python-argparse python-pip ssdeep-devel libffi-devel unrar upx unzip`

Installing Yara 
------------------

Make sure you are getting the latest and greatest version of Yara...
```
wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
tar -xvzf v3.4.0.tar.gz
cd yara-3.4.0/
./bootstrap.sh
./configure
make
sudo make install
```

Python Yara module install.
```
cd yara-python/
python setup.py build
sudo python setup.py install
```
Ensure those new libraries can be found.

`sudo vim /etc/ld.so.conf.d/yara.conf`

Add the line `/usr/local/lib`.

Reload necessary libraries.

`sudo ldconfig`

Python Modules
--------------

Install the following Python modules using `pip`.

```
sudo easy_install -U setuptools
sudo pip install czipfile pefile hachoir-parser hachoir-core hachoir-regex hachoir-metadata hachoir-subfile ConcurrentLogHandler pypdf2 xmltodict rarfile ssdeep pylzma oletools pyasn1_modules pyasn1
```
NOTE: Ensure pefile is at least version pefile-1.2.10-139. On some distros a latter version is installed which means you will need to build from source.

Install FSF
------------

Retrieve latest version of master.

```
cd ~
wget https://github.com/EmersonElectricCo/fsf/archive/master.zip
unzip master.zip
vim fsf-master/fsf-server/conf/config.py
```
Point `YARA_PATH` to the full path to `rules.yara`, in our case `/home/_username_/fsf-master/fsf-server/yara/rules.yara`.

Start the daemon.
```
cd fsf-master/fsf-server
./main.py start
```

Check how it is being locally hosted with a `netstat -na | grep 5800`, by default it is 127.0.0.1, but sometimes that needs to change, like here :)
```
netstat -na | grep 5800
tcp        0      0 127.0.1.1:5800          0.0.0.0:*               LISTEN
```

If necessary, change `IP_ADDRESS` in client config.

`vim ../fsf-client/conf/config.py`

Finally, test it out!
```
cd ../fsf-client/
./fsf_client.py ~/fsf-master/docs/Test.zip
```

Get all subobjects!

`./fsf_client.py ~/fsf-master/docs/Test.zip --full`

You should get a bunch of pretty JSON and a dump of subobjects if you use `--full`.

Problems? Check out `/tmp/daemon.log` and or `/tmp/dbg.log`.

Success? Awesome! If you have any ideas or desire to contribute modules or Yara signatures please share them!
