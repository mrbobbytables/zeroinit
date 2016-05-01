#!/bin/bash


if [ ! -f /.cloud_init_config_done ]; then
  rm -rf /var/lib/cloud/instance/*
  rm -rf /var/lib/cloud/seed/nocloud-net/meta-data
  rm -rf /var/lib/cloud/seed/nocloud-net/user-data

  echo "instance_id: $(hostname)" > /var/lib/cloud/seed/nocloud-net/meta-data

  cloud-init init
  cloud-init modules --mode init
  cloud-init modules --mode config
  cloud-init modules --mode final
else
  echo "cloud-init already executed."
fi

while true; do
  sleep 1
done
