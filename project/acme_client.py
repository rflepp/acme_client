import copy
import hashlib
import logging
import multiprocessing
import time
import http_server
import dnslib
import dnslib.server
import requests
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as default_backend
from cryptography import x509

logging.basicConfig()
logger = logging.getLogger("Client")
logger.setLevel(logging.DEBUG)


class Client:
    "Implementing the ACME Client"

    def __init__(self, challenge_type, dir_url, ipv4_address, domain, revoke):
        self.certificat = None
        self.cert_url = None
        self.order_url = None
        self.rsa_private_key = None
        self.finalize_url = None
        self.challenges = {}
        self.authorizations = None
        self.replay_nonce = None
        self.key_tuple = None
        self.kid = None
        self.rsa_jwk = None
        self.revokecert = None
        self.neworder = None
        self.newnonce = None
        self.newaccount = None
        self.keychange = None
        self.pebblecertificate = "pebble.minica.pem"
        self.dir_url = dir_url
        self.challengetype = challenge_type
        self.ipv4_address = ipv4_address
        self.domain = domain
        self.revoke = revoke
        self.acme_headers = {"User-Agent": "client", "Content-Type": "application/jose+json"}
        self.finalize_private_key = self.get_priv_key()
        self.dns_record_http = ". 60 IN A " + self.ipv4_address
        logger.info("creating instance of client")

    ### Helper functions ###
    def get_priv_key(self):
        priv_key = rsa.generate_private_key(
            key_size=2048,
            backend=default_backend(),
            public_exponent=65537
        )

        rsa_private_key = priv_key.private_bytes(
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
            encoding=serialization.Encoding.PEM
        )

        private_key_file = open("cert_priv_key.pem", "w")
        private_key_file.write(rsa_private_key.decode())
        private_key_file.close()

        return priv_key

    def to_b64(self, data):
        # encodes string as base64
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    def to_bytes(self, x):
        return x.to_bytes((x.bit_length() + 7) // 8, "big")

    def send_request(self, acme_url, protected, payload):
        msg = "{0}.{1}".format(protected, payload)
        sig = self.to_b64(self.key_tuple.sign(
            msg.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        ))
        data = {
            "protected": protected,
            "payload": payload,
            "signature": sig
        }
        reply = requests.post(url=acme_url, headers=self.acme_headers,
                              data=json.dumps(data), verify=self.pebblecertificate)
        if reply is not None:
            logger.info(reply)
            logger.info(reply.headers)
        self.replay_nonce = reply.headers["Replay-Nonce"]
        return reply

    def get_jws(self):
        # generate key_tuple and jwk
        self.key_tuple = rsa.generate_private_key(
            key_size=2048,
            backend=default_backend(),
            public_exponent=65537
        )

        rsa_private_key = self.key_tuple.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        rsa_public_key = self.key_tuple.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH
        )

        # Save key pair in files
        private_key_file = open("acme_rsa.pem", "w")
        private_key_file.write(rsa_private_key.decode())
        private_key_file.close()

        public_key_file = open("acme_rsa.pub", "w")
        public_key_file.write(rsa_public_key.decode())
        public_key_file.close()

        n = self.to_bytes(self.key_tuple.public_key().public_numbers().n)
        e = self.to_bytes(self.key_tuple.public_key().public_numbers().e)

        self.rsa_jwk = {
            "kty": "RSA",
            "n": self.to_b64(n),
            "e": self.to_b64(e)
        }

    def do_key_auth(self, token):
        # keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
        digest = hashlib.sha256(
            json.dumps(self.rsa_jwk, sort_keys=True, separators=(",", ":")).encode("utf8")).digest()
        tprint = self.to_b64(digest)
        return token + "." + tprint

    ### Non-Helper functions ###
    def setup(self):
        # send a request to the server to get the directory
        logger.info("Setup directory")
        directory = requests.get(url=self.dir_url, headers={"User-Agent": "client"},
                                 verify=self.pebblecertificate).json()
        logger.info(directory)
        self.keychange = directory["keyChange"]
        self.newaccount = directory["newAccount"]
        self.newnonce = directory["newNonce"]
        self.neworder = directory["newOrder"]
        self.revokecert = directory["revokeCert"]

        logger.info("Finished directories setup")
        logger.info("creating account")
        # Generate Key Pair
        self.get_jws()

        protected = self.to_b64(json.dumps({"alg": "RS256", "jwk": self.rsa_jwk, "nonce": self.get_nonce(),
                                            "url": self.newaccount}).encode("utf8"))
        payload = self.to_b64(json.dumps({"termsOfServiceAgreed": True}).encode("utf8"))

        new_acc_msg = self.send_request(self.newaccount, protected, payload)

        # Sometimes location is missing: do a check
        try:
            self.kid = new_acc_msg.headers["Location"]
        except KeyError:
            logger.info("Handling Keyerror in create_account")
            self.setup()

        logger.info("created new account")

    def get_nonce(self):
        # request a nonce
        logger.info("getting a nonce")
        nonce = requests.head(url=self.newnonce, headers={"User-Agent": "client"}, verify=self.pebblecertificate)
        logger.info(nonce.headers['Replay-Nonce'])
        return nonce.headers['Replay-Nonce']

    def submit_order(self):
        logger.info("Submitting order")

        domains_list = {"identifiers": []}
        for domain in self.domain:
            domains_list["identifiers"].append({"type": "dns", "value": domain[0]})
        protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                            "url": self.neworder}).encode("utf8"))
        payload = self.to_b64(json.dumps(domains_list).encode("utf8"))

        new_order_msg = self.send_request(self.neworder, protected, payload)
        new_order_msg_json = new_order_msg.json()

        try:
            self.authorizations = new_order_msg_json['authorizations']
            self.finalize_url = new_order_msg_json['finalize']
            self.order_url = new_order_msg.headers['Location']
        except KeyError:
            logger.info("Keyerror at submit_order")
            self.submit_order()
        logger.info("Done submitting order")

    def do_challenges(self):
        # getting challenges
        logger.info("Getting Challenges")
        for auth_url in self.authorizations:
            protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                                "url": auth_url}).encode("utf8"))
            reply = self.send_request(auth_url, protected, "").json()

            try:
                self.challenges[auth_url] = reply["challenges"]
            except KeyError:
                logger.info("Keyerror at get_challenges")
                self.do_challenges()

            logger.info("Got challenges")

        if self.challengetype == 'dns01':
            logger.info("Doing dns01 Challenges")
            self.do_dns01_challenge()

        elif self.challengetype == 'http01':
            logger.info("Doing http01 Challenges")
            self.do_https01_challenge()

    def do_dns01_challenge(self):
        for authz in self.challenges:
            for challenge in self.challenges[authz]:
                if challenge["type"] == "dns-01":
                    url = challenge["url"]
                    token = challenge["token"]
                    key_authorization = self.do_key_auth(token)
                    key_auth_digest = hashlib.sha256(key_authorization.encode("utf8")).digest()
                    sha_key_authorization = self.to_b64(key_auth_digest)
                    dns_record = [self.dns_record_http,
                                  "_acme-challenge.{0}. 300 IN TXT \"{1}\"".format(self.domain[0][0],
                                                                                   sha_key_authorization)]
                    resolver = Resolver("\n".join(dns_record))
                    server = dnslib.server.DNSServer(resolver, address=self.ipv4_address, port=10053)

                    server.start_thread()
                    protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                                        "url": url}).encode("utf8"))
                    logger.info("Sending Empty Message to server to signalize readyness")
                    self.send_request(url, protected, self.to_b64(json.dumps({}).encode("utf8"))).json()

                    # TODO: the client SHOULD NOT begin polling until it has
                    #    seen the validation request from the server.

                    self.polling(authz, "", "valid")
        return

    def do_https01_challenge(self):
        resolver = Resolver(self.dns_record_http)
        server = dnslib.server.DNSServer(resolver, address=self.ipv4_address, port=10053)
        server.start_thread()
        for authz in self.challenges:
            for challenge in self.challenges[authz]:
                if challenge["type"] == "http-01":
                    url = challenge["url"]
                    token = challenge["token"]
                    key_authorization = self.do_key_auth(token)

                    chall_server = multiprocessing.Process(
                        target=http_server.run_chall_server,
                        args=(token, key_authorization, self.ipv4_address, logger)
                    )
                    chall_server.start()

                    protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                                        "url": url}).encode("utf8"))
                    logger.info("Sending Empty Message to server to signalize readyness")
                    self.send_request(url, protected, self.to_b64(json.dumps({}).encode("utf8"))).json()

                    self.polling(authz, "", "valid")
                    chall_server.terminate()
                    chall_server.join()
        return

    def polling(self, url, payload, wanted_status):
        logger.info("Polling...")

        for i in range(1, 10):
            protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                                "url": url}).encode("utf8"))
            logger.info("Polling for the {0} time.".format(i))
            reply = self.send_request(url, protected, payload).json()
            status = reply["status"]
            if status == "invalid":
                raise Exception("Got invalid status")
                exit()
            elif status == wanted_status:
                return reply
                exit()
            time.sleep(1)

    def finalize(self):
        # send finalize order to finalize url and download the certificate
        logger.info("Finalizing")
        CSRBuilder = x509.CertificateSigningRequestBuilder()
        hostnames = []
        for domain in self.domain:
            hostnames.append(x509.DNSName(domain[0]))

        CSRBuilder = CSRBuilder.subject_name(
            x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, self.domain[0][0])
            ])
        )
        CSRBuilder = CSRBuilder.add_extension(
            x509.SubjectAlternativeName(hostnames), critical=False)
        CSRBuilder = CSRBuilder.sign(self.finalize_private_key, hashes.SHA256(), default_backend())
        csr_pem = CSRBuilder.public_bytes(serialization.Encoding.DER)

        payload = self.to_b64(json.dumps({"csr": self.to_b64(csr_pem)}).encode("utf8"))

        protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                            "url": self.finalize_url}).encode("utf8"))
        self.send_request(self.finalize_url, protected, payload)
        reply = self.polling(self.order_url, "", "valid")
        self.cert_url = reply['certificate']

        logger.info("Done with finalizing")

        logger.info("Downloading certificate")
        protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                            "url": self.cert_url}).encode("utf8"))
        reply = self.send_request(self.cert_url, protected, "")
        # saving the certificat
        certificat = x509.load_pem_x509_certificate(reply.content, default_backend())
        self.certificat = certificat.public_bytes(serialization.Encoding.DER)

        cert_file = open("acme_cert.pem", "wb")
        cert_file.write(reply.text.encode("utf-8"))
        cert_file.close()

    def revoke_cert(self):
        logger.info("Revoke certificate")
        payload = self.to_b64(json.dumps({"certificate": self.to_b64(self.certificat)}).encode("utf8"))
        protected = self.to_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.replay_nonce,
                                            "url": self.revokecert}).encode("utf8"))
        reply = self.send_request(self.revokecert, protected, payload)
        logger.info("Revoked Certificate")

    def run_http(self):
        logger.info("Starting to run Http Servers")
        sd_listener = multiprocessing.Process(
            target=http_server.run_sd_server,
            args=(self.ipv4_address, logger)
        )
        cert_thread = multiprocessing.Process(
            target=http_server.run_cert_server,
            args=(self.ipv4_address, logger)
        )

        cert_thread.start()
        sd_listener.start()

        while sd_listener.is_alive():
            pass
        sd_listener.terminate()
        cert_thread.terminate()


class Resolver(dnslib.server.BaseResolver):
    # Resolver for the DNS Server
    def __init__(self, addr):
        self.address = dnslib.dns.RR.fromZone(addr)

    def resolve(self, req, handler):
        reply = req.reply()
        q = req.q.qname

        # Go through all the entries
        for entry in self.address:
            answer = copy.copy(entry)
            answer.rname = q
            reply.add_answer(answer)
        return reply
