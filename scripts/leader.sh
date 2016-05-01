#!/bin/bash

main() {
  echo "[masters]" > /etc/ansible/hosts
  for master in "$@"; do
    echo "$master" >> /etc/ansible/hosts
  done
 
  ansible-playbook --private-key=/etc/ansible/keys/bootstrap/id_rsa /etc/ansible/bootstrap_masters.yml
  
}

main "$@"
