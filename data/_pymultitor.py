import re
import sys
import json
import atexit
import socket
import logging
import requests
import platform
import itertools
from os import path
from shutil import rmtree
from mitmproxy import ctx
from tempfile import mkdtemp
from mitmproxy.http import HTTPResponse
from mitmproxy.tools.main import mitmdump
from multiprocessing.pool import ThreadPool
from stem.control import Controller, Signal
from requests.exceptions import ConnectionError
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from stem.process import launch_tor_with_config, DEFAULT_INIT_TIMEOUT

__version__ = '3.2.0'


def is_windows():
    return platform.system().lower() == 'windows'


class Tor(object):
    def __init__(self, cmd='tor', timeout=DEFAULT_INIT_TIMEOUT, config=None):
        self.logger = logging.getLogger(__name__)
        self.tor_cmd = cmd
        self.tor_timeout = timeout
        self.tor_config = config or {}
        self.socks_port = self.free_port()
        self.control_port = self.free_port()
        self.data_directory = mkdtemp()
        self.id = self.socks_port
        self.process = None
        self.controller = None
        self.__is_shutdown = False

    def __del__(self):
        self.shutdown()

    def __enter__(self):
        return self.run()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def run(self):
        self.logger.debug("[%05d] Executing Tor Process" % self.id)
        try:
            self.process = launch_tor_with_config(
                config={
                    "ControlPort": str(self.control_port),
                    "SOCKSPort": str(self.socks_port),
                    "DataDirectory": self.data_directory,
                    "AllowSingleHopCircuits": "1",
                    "ExcludeSingleHopRelays": "0",
                    **self.tor_config
                },
                tor_cmd=self.tor_cmd,
                timeout=self.tor_timeout or None,
                init_msg_handler=self.print_bootstrapped_line
            )
        except Exception as e:
            self.logger.error("[%05d] Failed To Launch Tor Process: %s" % (self.id, str(e)))
            self.__is_shutdown = True
            return self

        self.logger.debug("[%05d] Creating Tor Controller" % self.id)
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate()

        return self

    def shutdown(self):
        if self.__is_shutdown:
            return

        self.__is_shutdown = True
        self.logger.debug("[%05d] Destroying Tor" % self.id)
        self.controller.close()
        self.process.terminate()
        self.process.wait()

        # If Not Closed Properly
        if path.exists(self.data_directory):
            rmtree(self.data_directory)

    def newnym_available(self):
        return self.controller.is_newnym_available()

    def newnym(self):
        if not self.newnym_available():
            self.logger.warning("[%05d] Cant Change Tor Identity (Need More Tor Processes)" % self.id)
            return False

        self.logger.info("[%05d] Changing Tor Identity" % self.id)
        self.controller.signal(Signal.NEWNYM)
        return True

    def print_bootstrapped_line(self, line):
        if "Bootstrapped" in line:
            self.logger.debug("[%05d] Tor Bootstrapped Line: %s" % (self.id, line))

            if "100%" in line:
                self.logger.debug("[%05d] Tor Process Executed Successfully" % self.id)

    @staticmethod
    def free_port():
        """
        Determines a free port using sockets.
        Taken from selenium python.
        """
        free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free_socket.bind(('0.0.0.0', 0))
        free_socket.listen(5)
        port = free_socket.getsockname()[1]
        free_socket.close()
        return port


class MultiTor(object):
    def __init__(self, size=2, cmd='tor', timeout=DEFAULT_INIT_TIMEOUT, config=None):
        self.logger = logging.getLogger(__name__)
        self.cmd = cmd
        self.timeout = timeout
        self.size = size
        self.list = []
        self.cycle = None
        self.current = None
        try:
            self.config = self.parse_config(config)
        except Exception as error:
            print(error, config, type(config))

    def parse_config(self, config=None):
        config = config or {}

        cfg = {}
        try:
            if isinstance(config, dict):
                cfg = config
            elif path.isfile(config):
                with open(config, encoding='utf-8') as cfg_file:
                    json.load(cfg_file)
            else:
                cfg = json.loads(config)
        except (TypeError, json.JSONDecodeError):
            self.logger.error("Could Not Parse Extended JSON Configuration %s" % repr(config))
            return {}
        except Exception as error:
            self.logger.error("Got Unknown Error %s" % error)
            return {}

        # Remove Port / Data Configurations
        cfg.pop('ControlPort', None)
        cfg.pop('SOCKSPort', None)
        cfg.pop('DataDirectory', None)

        self.logger.debug("Extended Configuration: %s" % json.dumps(cfg))
        return cfg

    def run(self):
        self.logger.info("Executing %d Tor Processes" % self.size)

        # If OS Platform Is Windows Run Processes Async
        if is_windows():
            pool = ThreadPool(processes=self.size)
            self.list = pool.map(lambda _: Tor(cmd=self.cmd, timeout=self.timeout, config=self.config).run(), range(self.size))
        else:
            self.list = [Tor(cmd=self.cmd, timeout=self.timeout, config=self.config).run() for _ in range(self.size)]

        self.logger.info("All Tor Processes Executed Successfully")
        self.cycle = itertools.cycle(self.list)
        self.current = next(self.cycle)

    @property
    def proxy(self):
        proxy_url = 'socks5://127.0.0.1:%d' % self.current.socks_port
        return {'http': proxy_url, 'https': proxy_url}

    def new_identity(self):
        self.current.newnym()
        self.current = next(self.cycle)

        return self.proxy

    def shutdown(self):
        for tor in self.list:
            tor.shutdown()


class PyMultiTor(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.insecure = False

        # Change IP Policy (Configuration)
        self.counter = itertools.count(1)
        self.on_count = 0
        self.on_string = ""
        self.on_regex = ""
        self.on_rst = False
        self.on_error_code = 0

        self.multitor = None

    @staticmethod
    def load(loader):
        # MultiTor Configuration
        loader.add_option(
            name="tor_processes",
            typespec=int,
            default=2,
            help="number of tor processes in the cycle",
        )
        loader.add_option(
            name="tor_cmd",
            typespec=str,
            default='tor',
            help="tor cmd (executable path + arguments)",
        )
        loader.add_option(
            name="tor_timeout",
            typespec=int,
            default=DEFAULT_INIT_TIMEOUT,
            help="number of seconds before we time out our attempt to start a tor instance",
        )
        loader.add_option(
            name="tor_config",
            typespec=str,
            default="{}",
            help="tor extended json configuration",
        )

        # When To Change IP Address
        loader.add_option(
            name="on_count",
            typespec=int,
            default=0,
            help="change ip every x requests (resources also counted)",
        )
        loader.add_option(
            name="on_string",
            typespec=str,
            default="",
            help="change ip when string found in the response content",
        )
        loader.add_option(
            name="on_regex",
            typespec=str,
            default="",
            help="change ip when regex found in The response content",
        )
        loader.add_option(
            name="on_rst",
            typespec=bool,
            default=False,
            help="change ip when connection closed with tcp rst",
        )
        loader.add_option(
            name="on_error_code",
            typespec=int,
            default=0,
            help="change ip when a specific status code returned",
        )

    def configure(self, updates):
        # Configure Logger
        logging.basicConfig(level=logging.DEBUG if ctx.options.termlog_verbosity.lower() == 'debug' else logging.INFO,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%d-%m-%y %H:%M:%S')

        # Disable Other Loggers
        logging.getLogger("stem").disabled = True
        logging.getLogger("requests.packages.urllib3.connectionpool").disabled = True

        # Log CMD Args If Debug Mode Enabled
        self.logger.debug("Running With CMD Args: %s" % json.dumps({
            update: getattr(ctx.options, update) for update in updates
        }))

        self.on_count = ctx.options.on_count
        self.on_string = str.encode(ctx.options.on_string)
        self.on_regex = ctx.options.on_regex
        self.on_rst = ctx.options.on_rst
        self.on_error_code = ctx.options.on_error_code

        self.insecure = ctx.options.ssl_insecure

        self.multitor = MultiTor(
            size=ctx.options.tor_processes,
            cmd=ctx.options.tor_cmd,
            timeout=ctx.options.tor_timeout,
            config=ctx.options.tor_config
        )
        try:
            self.multitor.run()
        except KeyboardInterrupt:
            self.multitor.shutdown()

        atexit.register(self.multitor.shutdown)

        # Warn If No Change IP Configuration:
        if not (self.on_count or self.on_string or self.on_regex or self.on_rst or self.on_error_code):
            self.logger.warning("Change IP Configuration Not Set (Acting As Regular Tor Proxy)")

    def create_response(self, request):
        response = requests.request(
            method=request.method,
            url=request.url,
            data=request.content,
            headers=request.headers,
            allow_redirects=False,
            verify=not self.insecure,
            proxies=self.multitor.proxy
        )

        return HTTPResponse.make(
            status_code=response.status_code,
            content=response.content,
            headers=dict(response.headers),
        )

    def request(self, flow):
        try:
            flow.response = self.create_response(flow.request)
        except ConnectionError:
            # If TCP Rst Configured
            if self.on_rst:
                self.logger.debug("Got TCP Rst, While TCP Rst Configured")
                self.multitor.new_identity()
                # Set Response
                try:
                    flow.response = self.create_response(flow.request)
                except Exception as error:
                    self.logger.error("Got Unknown Error (after second TCP Rst) %s" % error)
                    flow.response = HTTPResponse.make(400, "Unknown Error (after second TCP Rst) %s" % error)
                    return
            else:
                self.logger.error("Got TCP Rst, While TCP Rst Not Configured")
                flow.response = HTTPResponse.make(400, "Got TCP Rst")
                return
        except Exception as error:
            self.logger.error("Got Unknown Error %s" % error)
            flow.response = HTTPResponse.make(400, "Unknown Error %s" % error)
            return

        # If String Found In Response Content
        if self.on_string and self.on_string in flow.response.text:
            self.logger.debug("String Found In Response Content")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)

        # If Regex Found In Response Content
        if self.on_regex and re.search(self.on_regex, flow.response.text, re.IGNORECASE):
            self.logger.debug("Regex Found In Response Content")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)

        # If Counter Raised To The Configured Number
        if self.on_count and next(self.counter) >= self.on_count:
            self.logger.debug("Counter Raised To The Configured Number")
            self.counter = itertools.count(1)
            self.multitor.new_identity()

        # If A Specific Status Code Returned
        if self.on_error_code and self.on_error_code == flow.response.status_code:
            self.logger.debug("Specific Status Code Returned")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {ver}".format(ver=__version__))

    # Proxy Configuration
    parser.add_argument("-lh", "--host",
                        help="proxy listen host.",
                        dest="listen_host",
                        default="127.0.0.1")
    parser.add_argument("-lp", "--port",
                        help="proxy listen port",
                        dest="listen_port",
                        type=int,
                        default=8080)
    parser.add_argument("-s", "--socks",
                        help="use as socks proxy (not http proxy)",
                        action='store_true')
    parser.add_argument("-a", "--auth",
                        help="set proxy authentication (format: 'username:pass')",
                        dest="auth",
                        default="")
    parser.add_argument("-i", "--insecure",
                        help="insecure ssl",
                        action='store_true')
    parser.add_argument("-d", "--debug",
                        help="Debug Log.",
                        action="store_true")

    # MultiTor Configuration
    parser.add_argument("-p", "--tor-processes",
                        help="number of tor processes in the cycle",
                        dest="processes",
                        type=int,
                        default=2)
    parser.add_argument("-c", "--tor-cmd",
                        help="tor cmd (executable path + arguments)",
                        dest="cmd",
                        default="tor")
    parser.add_argument("-t", "--tor-timeout",
                        help="number of seconds before we time out our attempt to start a tor instance",
                        dest="timeout",
                        type=int,
                        default=DEFAULT_INIT_TIMEOUT)
    parser.add_argument("-e", "--tor-config",
                        help="tor extended json configuration",
                        dest="config",
                        default="{}")

    # When To Change IP Address
    parser.add_argument("--on-count",
                        help="change ip every x requests (resources also counted)",
                        type=int,
                        default=0)
    parser.add_argument("--on-string",
                        help="change ip when string found in the response content",
                        default="")
    parser.add_argument("--on-regex",
                        help="change ip when regex found in The response content",
                        default="")
    parser.add_argument("--on-rst",
                        help="change ip when connection closed with tcp rst",
                        action="store_true")
    parser.add_argument("--on-error-code",
                        help="change ip when a specific status code returned",
                        type=int,
                        default=0)

    sys_args = vars(parser.parse_args(args=args))
    mitmdump_args = [
        '--scripts', __file__,
        '--mode', 'socks5' if sys_args['socks'] else 'regular',
        '--listen-host', sys_args['listen_host'],
        '--listen-port', str(sys_args['listen_port']),
        '--set', f'tor_cmd={sys_args["cmd"]}',
        '--set', f'tor_timeout={sys_args["timeout"]}',
        '--set', f'tor_config={sys_args["config"]}',
        '--set', f'tor_processes={sys_args["processes"]}',
        '--set', f'on_string={sys_args["on_string"]}',
        '--set', f'on_regex={sys_args["on_regex"]}',
        '--set', f'on_count={sys_args["on_count"]}',
        '--set', f'on_error_code={sys_args["on_error_code"]}',
    ]
    if sys_args['auth']:
        mitmdump_args.extend([
            '--proxyauth', sys_args["auth"],
        ])

    if sys_args['on_rst']:
        mitmdump_args.extend([
            '--set', f'on_rst',
        ])

    if sys_args['debug']:
        mitmdump_args.extend([
            '--verbose',
        ])

    if sys_args['insecure']:
        mitmdump_args.extend([
            '--ssl-insecure',
        ])
    return mitmdump(args=mitmdump_args)


addons = [
    PyMultiTor()
]

if __name__ == "__main__":
    main()
