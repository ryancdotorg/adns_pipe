#!/bin/bash

cat > ec2.sh <<EoFa
#!/bin/bash

apt-get update
apt-get -y install libc-ares2 iftop xz-utils lzma

echo 'ubuntu		soft	nofile		16384' >> /etc/security/limits.conf
echo 'ubuntu		hard	nofile		32768' >> /etc/security/limits.conf

(base64 -d | xzcat > /home/ubuntu/adns_pipe) <<EoF
EoFa
cp adns_pipe adns_pipe.stripped
strip adns_pipe.stripped
lzma -9 adns_pipe.stripped
base64 < adns_pipe.stripped.lzma >> ec2.sh
rm adns_pipe.stripped.lzma
cat >> ec2.sh <<EoFb
EoF
chmod +x /home/ubuntu/adns_pipe
chown ubuntu.ubuntu /home/ubuntu/adns_pipe
#apt-get -y upgrade
EoFb
if [ -e ec2.sh.gz ]
then
	rm ec2.sh.gz
fi
gzip -9 ec2.sh
ls -al ec2.sh.gz
