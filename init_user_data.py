#!/usr/bin/env python
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import logging
import os
import sys
import yaml
from Crypto.PublicKey import RSA


def str_presenter(dumper, data):
  if len(data.splitlines()) > 1:  # check for multiline string
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  else:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

yaml.add_representer(str, str_presenter)

logging.basicConfig(format='[%(asctime)s][%(levelname)s][%(module)s][%(name)s][%(funcName)s] %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)



def main(args):
    log.info('Generating new RSA keypair.')
    key = RSA.generate(2048, os.urandom)
    priv_key = key.exportKey('PEM')
    pub_key = key.publickey().exportKey('OpenSSH')

    with open('keys/bootstrap_rsa', 'w') as f:
        f.write(priv_key)

    with open('keys/bootstrap_rsa.pub', 'w') as f:
        f.write(pub_key)

    log.info('Bootstrap keys saved to keys directory.')

    log.info('Loading template from cloud-config/user-data.tmplt')
    with open('cloud-config/user-data.tmplt', 'r') as f:
        user_data = yaml.load(f.read())

    user_data['users'][0]['ssh-authorized-keys'][0] = pub_key
    user_data['write_files'][1]['content'] = priv_key
    user_data['write_files'][2]['content'] = pub_key

    with open('cloud-config/user-data', 'w') as f:
        f.write('#cloud-config\n')
        f.write(yaml.dump(user_data, default_flow_style=False))

    log.info('user-data template rendered. Ready to use.')

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
