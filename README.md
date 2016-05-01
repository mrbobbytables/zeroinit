# Zeroinit

A small project using a combination of zeroconf, cloud-config, and ansible to elect a leader and perform initial key rotation & bootstrapping for masters in a cluster.

### Usage

1. Perform ``docker-compose build`` to build the zeroinit container.
2. Execute ``./init_user_data.py`` to generate an initial key pair and update the cloud-config template.
3. Execute ``docker-compose up -d`` followed by ``docker-compose scale master=3`` to bring up 3 nodes.
4. Follow the logs of node with the lowest IP address (likely ``zeroinit_master_1``). With ``docker logs -f <container name>``.
5. Verify the keys have been rotated and the provision user added by performing the following:
  *  ``docker exec zeroinit_master_1 /bin/bash``
  *  ``export TERM=xterm``
  *  ``ssh -i /etc/ansible/keys/provision/id_rsa provision@<ip of other node>``



### How it works

The cloud-config file has been seeded with an RSA key pair for use with initial bootstrapping. This key does not need to remain secure as it will be rotated out almost immediately after booting.

As part of the final steps of configuration, cloud-init calls a python script with: ``./bootstrap.py --iface eth0 --expect 3 --log_level info --action ./leader.sh``

This script will both listen and announce on the specified interface that it is a master and broadcast its election ID: the first IP associated with the interface converted to an integer. Once the nodes discover the expected number of masters, leader election begins.

The leader is simply the system with the lowest value of the election ID. The leader will then broadcast that it has assumed the leader role and will halt the initial discovery broadcast. The other nodes will then stop broadcasting, and for them the bootstrap script will terminate.

For the leader, it will wait until it no longer detects any other systems broadcasting on the discovery service and then move to perform the supplied action (defaults to simply ``echo``). The action will then be executed and passed a space-delimited list of the discovered IP addresses.

In this example, it calls a script ``scripts/leader.sh``. This script injects the IPs it discovered into an ansible host group then calls ansible to execute a playbook.

The playbook first executes solely on the elected leader, generating a new RSA key pair.

Once the keypair is generated, the leader will then connect to the other nodes and inject this newly generated key, and lastly revoking the initial bootstrap key.

Any further plays can then be executed with the new key.


