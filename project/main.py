import argparse
import logging
from acme_client import Client

# 2nd try
# Parse command line input
# TODO: check for correct input?
parser = argparse.ArgumentParser(description='Process Input.')
parser.add_argument('challenge_type', choices=['http01', 'dns01'])
parser.add_argument('--dir', required=True)
parser.add_argument('--record', required=True)
parser.add_argument('--domain', required=True, nargs='*', action='append')
parser.add_argument('--revoke', action='store_true')
args = parser.parse_args()

# Global variables
CHALLENGE_TYPE = args.challenge_type
DIR_URL = args.dir
IPv4_ADDRESS = args.record
DOMAIN = args.domain
REVOKE = args.revoke

# Create ACME Client Object and Account on Server
acme_client = Client(CHALLENGE_TYPE, DIR_URL, IPv4_ADDRESS, DOMAIN, REVOKE)
directory = acme_client.setup()
acme_client.submit_order()
acme_client.do_challenges()
acme_client.finalize()
if(REVOKE):
    acme_client.revoke_cert()
acme_client.run_http()
logging.info(args)
