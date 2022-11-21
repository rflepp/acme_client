import socketserver
import http.server
import ssl
import flask


def run_cert_server(addr, logger) -> None:
    keyfile = "cert_priv_key.pem"
    certfile = "acme_cert.pem"
    logger.info("Starting Http Server")
    server_deamon = http.server.HTTPServer((addr, 5001), http.server.SimpleHTTPRequestHandler)
    server_deamon.socket = ssl.wrap_socket(server_deamon.socket, keyfile=keyfile, certfile=certfile,
                                           server_side=True)
    server_deamon.allow_reuse_address = True
    server_deamon.serve_forever()


def run_sd_server(addr, logger) -> None:
    logger.info("Starting Shutdown Http Server")
    shutdown_deamon = socketserver.TCPServer((addr, 5003), RequestHandlerClass=Handler)
    shutdown_deamon.handle_request()
    shutdown_deamon.allow_reuse_address = True
    logger.info("Shutting down")
    shutdown_deamon.server_close()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        """Respond to a GET request."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()


def run_chall_server(token, key_authorization, ipv4_address, logger):
    app = flask.Flask(__name__)
    logger.info("running http_chall server")

    @app.route("/.well-known/acme-challenge/" + token)
    def challenge_response():
        return key_authorization

    app.run(host=ipv4_address, port=5002, debug=True)
