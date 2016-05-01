FROM ubuntu:14.04

RUN apt-get -y update  \
 && apt-get -y install \
    cloud-init         \
    openssh-server

COPY ./cloud_init.sh /

RUN chmod +x ./cloud_init.sh

CMD ./cloud_init.sh
