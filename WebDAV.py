import argparse
import copy
import logging
import multiprocessing
import os
import platform
import sys
import yaml
from pprint import pformat
from threading import Timer
from wsgidav import __version__, util
from wsgidav.default_conf import DEFAULT_CONFIG, DEFAULT_VERBOSE
from wsgidav.fs_dav_provider import FilesystemProvider
from wsgidav.wsgidav_app import WsgiDAVApp

try:
    from pyjson5 import load as json_load
except ImportError:
    from json5 import load as json_load

from PySide6.QtCore import (QByteArray, QMetaObject, QRect,
                            QSize, Qt, QLocale, QTranslator, QLibraryInfo)
from PySide6.QtGui import (QFont, QIcon,
                           QImage, QPixmap)
from PySide6.QtWidgets import (QApplication, QLabel, QPushButton, QLineEdit, QMainWindow)
from PySide6.QtNetwork import QHostInfo

__docformat__ = "reStructuredText"
DEFAULT_CONFIG_FILES = ("wsgidav.yaml", "wsgidav.json")
_logger = logging.getLogger("wsgidav")

class FullExpandedPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        new_val = os.path.abspath(os.path.expanduser(values))
        setattr(namespace, self.dest, new_val)

class WebDAV(object):
    def __init__(self, running_path='./'):
        self.running_path = running_path

    def _get_common_info(self, config):
        ssl_certificate = util.fix_path(config.get("ssl_certificate"), config)
        ssl_private_key = util.fix_path(config.get("ssl_private_key"), config)
        ssl_certificate_chain = util.fix_path(config.get("ssl_certificate_chain"), config)
        ssl_adapter = config.get("ssl_adapter", "builtin")
        use_ssl = False
        if ssl_certificate and ssl_private_key:
            use_ssl = True
        elif ssl_certificate or ssl_private_key:
            raise RuntimeError(
                "Option 'ssl_certificate' and 'ssl_private_key' must be used together."
            )
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{config['host']}:{config['port']}"
        info = {
            "use_ssl": use_ssl,
            "ssl_cert": ssl_certificate,
            "ssl_pk": ssl_private_key,
            "ssl_adapter": ssl_adapter,
            "ssl_chain": ssl_certificate_chain,
            "protocol": protocol,
            "url": url,
        }
        return info

    def _init_command_line_options(self):
        """Parse command line options into a dictionary."""
        description = """\

    Run a WEBDAV server to share file system folders.

    Examples:

      Share filesystem folder '/temp' for anonymous access (no config file used):
        wsgidav --port=80 --host=0.0.0.0 --root=/temp --auth=anonymous

      Run using a specific configuration file:
        wsgidav --port=80 --host=0.0.0.0 --config=~/my_wsgidav.yaml

      If no config file is specified, the application will look for a file named
      'wsgidav.yaml' in the current directory.
      See
        http://wsgidav.readthedocs.io/en/latest/run-configure.html
      for some explanation of the configuration file format.
      """

        epilog = """\
    Licensed under the MIT license.
    See https://github.com/mar10/wsgidav for additional information.

    """
        SUPPORTED_SERVERS = {
            "cheroot": self._run_cheroot,
            "ext-wsgiutils": self._run_ext_wsgiutils,
            "gevent": self._run_gevent,
            "gunicorn": self._run_gunicorn,
            "paste": self._run_paste,
            "uvicorn": self._run_uvicorn,
            "wsgiref": self._run_wsgiref,
        }
        parser = argparse.ArgumentParser(
            prog="wsgidav",
            description=description,
            epilog=epilog,
            allow_abbrev=False,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "-p",
            "--port",
            type=int,
            help="port to serve on (default: 8080)",
        )
        parser.add_argument(
            "-H",
            "--host",
            help=(
                "host to serve from (default: localhost). 'localhost' is only "
                "accessible from the local computer. Use 0.0.0.0 to make your "
                "application public"
            ),
        )
        parser.add_argument(
            "-r",
            "--root",
            dest="root_path",
            action=FullExpandedPath,
            help="path to a file system folder to publish as share '/'.",
        )
        parser.add_argument(
            "--auth",
            choices=("anonymous", "nt", "pam-login"),
            help="quick configuration of a domain controller when no config file "
                 "is used",
        )
        qv_group = parser.add_mutually_exclusive_group()
        qv_group.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=3,
            help="increment verbosity by one (default: %(default)s, range: 0..5)",
        )
        args = parser.parse_args()
        if args.root_path and not os.path.isdir(args.root_path):
            msg = "{} is not a directory".format(args.root_path)
            parser.error(msg)
        args.port = 8080
        args.host = '0.0.0.0'
        args.root_path = self.running_path
        args.auth = 'anonymous'
        cmdLineOpts = args.__dict__.copy()
        if args.verbose >= 5:
            print("Command line args:")
            for k, v in cmdLineOpts.items():
                print("    {:>12}: {}".format(k, v))
        return cmdLineOpts, parser

    def _read_config_file(self, config_file, _verbose):
        config_file = os.path.abspath(config_file)
        if not os.path.exists(config_file):
            raise RuntimeError(f"Couldn't open configuration file '{config_file}'.")
        if config_file.endswith(".json"):
            with open(config_file, mode="rt", encoding="utf-8-sig") as fp:
                conf = json_load(fp)
        elif config_file.endswith(".yaml"):
            with open(config_file, mode="rt", encoding="utf-8-sig") as fp:
                conf = yaml.safe_load(fp)
        else:
            raise RuntimeError(
                f"Unsupported config file format (expected yaml or json): {config_file}"
            )
        conf["_config_file"] = config_file
        conf["_config_root"] = os.path.dirname(config_file)
        return conf

    def _init_config(self):
        cli_opts, parser = self._init_command_line_options()
        cli_verbose = cli_opts["verbose"]
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["_config_file"] = None
        config["_config_root"] = os.getcwd()
        config_file = cli_opts.get("config_file")
        if config_file:
            file_opts = self._read_config_file(config_file, cli_verbose)
            util.deep_update(config, file_opts)
            if cli_verbose != DEFAULT_VERBOSE and "verbose" in file_opts:
                if cli_verbose >= 2:
                    print(
                        "Config file defines 'verbose: {}' but is overridden by command line: {}.".format(
                            file_opts["verbose"], cli_verbose
                        )
                    )
                config["verbose"] = cli_verbose
        else:
            if cli_verbose >= 2:
                print("Running without configuration file.")
        if cli_opts.get("port"):
            config["port"] = cli_opts.get("port")
        if cli_opts.get("host"):
            config["host"] = cli_opts.get("host")
        if cli_opts.get("profile") is not None:
            config["profile"] = True
        if cli_opts.get("server") is not None:
            config["server"] = cli_opts.get("server")
        if cli_opts.get("ssl_adapter") is not None:
            config["ssl_adapter"] = cli_opts.get("ssl_adapter")
        if cli_opts.get("verbose") != DEFAULT_VERBOSE:
            config["verbose"] = cli_opts.get("verbose")
        if cli_opts.get("root_path"):
            root_path = os.path.abspath(cli_opts.get("root_path"))
            config["provider_mapping"]["/"] = FilesystemProvider(root_path)
        if config["verbose"] >= 5:
            config_cleaned = util.purge_passwords(config)
            print(
                "Configuration({}):\n{}".format(
                    cli_opts["config_file"], pformat(config_cleaned)
                )
            )

        if not config["provider_mapping"]:
            parser.error("No DAV provider defined.")

        auth = cli_opts.get("auth")
        auth_conf = util.get_dict_value(config, "http_authenticator", as_dict=True)
        if auth and auth_conf.get("domain_controller"):
            parser.error(
                "--auth option can only be used when no domain_controller is configured"
            )

        if auth == "anonymous":
            if config["simple_dc"]["user_mapping"]:
                parser.error(
                    "--auth=anonymous can only be used when no user_mapping is configured"
                )
            auth_conf.update(
                {
                    "domain_controller": "wsgidav.dc.simple_dc.SimpleDomainController",
                    "accept_basic": True,
                    "accept_digest": True,
                    "default_to_digest": True,
                }
            )
            config["simple_dc"]["user_mapping"] = {"*": True}
        elif auth == "nt":
            if config.get("nt_dc"):
                parser.error(
                    "--auth=nt can only be used when no nt_dc settings are configured"
                )
            auth_conf.update(
                {
                    "domain_controller": "wsgidav.dc.nt_dc.NTDomainController",
                    "accept_basic": True,
                    "accept_digest": False,
                    "default_to_digest": False,
                }
            )
            config["nt_dc"] = {}
        elif auth == "pam-login":
            if config.get("pam_dc"):
                parser.error(
                    "--auth=pam-login can only be used when no pam_dc settings are configured"
                )
            auth_conf.update(
                {
                    "domain_controller": "wsgidav.dc.pam_dc.PAMDomainController",
                    "accept_basic": True,
                    "accept_digest": False,
                    "default_to_digest": False,
                }
            )
            config["pam_dc"] = {"service": "login"}

        return cli_opts, config

    def _run_cheroot(self, app, config, _server):
        try:
            from cheroot import server, wsgi
        except ImportError:
            _logger.exception("Could not import Cheroot (https://cheroot.cherrypy.dev/).")
            _logger.error("Try `pip install cheroot`.")
            return False

        version = wsgi.Server.version
        version = f"WsgiDAV/{__version__} {version} Python {util.PYTHON_VERSION}"
        wsgi.Server.version = version
        info = self._get_common_info(config)
        if info["use_ssl"]:
            ssl_adapter = info["ssl_adapter"]
            ssl_adapter = server.get_ssl_adapter_class(ssl_adapter)
            wsgi.Server.ssl_adapter = ssl_adapter(
                info["ssl_cert"], info["ssl_pk"], info["ssl_chain"]
            )
            _logger.info("SSL / HTTPS enabled. Adapter: {}".format(ssl_adapter))

        _logger.info(f"Running {version}")
        _logger.info(f"Serving on {info['url']} ...")

        server_args = {
            "bind_addr": (config["host"], config["port"]),
            "wsgi_app": app,
            "server_name": version,
            "numthreads": 50,
        }
        custom_args = util.get_dict_value(config, "server_args", as_dict=True)
        server_args.update(custom_args)

        class PatchedServer(wsgi.Server):
            STARTUP_NOTIFICATION_DELAY = 0.5

            def serve(self, *args, **kwargs):
                _logger.error("wsgi.Server.serve")
                if startup_event and not startup_event.is_set():
                    Timer(self.STARTUP_NOTIFICATION_DELAY, startup_event.set).start()
                    _logger.error("wsgi.Server is ready")
                return super().serve(*args, **kwargs)

        startup_event = config.get("startup_event")
        if startup_event:
            server = PatchedServer(**server_args)
        else:
            server = wsgi.Server(**server_args)

        try:
            server.start()
        except KeyboardInterrupt:
            _logger.warning("Caught Ctrl-C, shutting down...")
        finally:
            server.stop()
        return

    def _run_ext_wsgiutils(self, app, config, _server):
        from wsgidav.server import ext_wsgiutils_server

        _logger.warning(
            "WARNING: This single threaded server (ext-wsgiutils) is not meant for production."
        )
        try:
            ext_wsgiutils_server.serve(config, app)
        except KeyboardInterrupt:
            _logger.warning("Caught Ctrl-C, shutting down...")
        return

    def _run_gevent(self, app, config, server):
        try:
            import gevent
            import gevent.monkey
            from gevent.pywsgi import WSGIServer
        except ImportError:
            _logger.exception("Could not import gevent (http://www.gevent.org).")
            _logger.error("Try `pip install gevent`.")
            return False
        gevent.monkey.patch_all()
        info = self._get_common_info(config)
        version = f"gevent/{gevent.__version__}"
        version = f"WsgiDAV/{__version__} {version} Python {util.PYTHON_VERSION}"
        server_args = {
            "wsgi_app": app,
            "bind_addr": (config["host"], config["port"]),
        }
        custom_args = util.get_dict_value(config, "server_args", as_dict=True)
        server_args.update(custom_args)
        if info["use_ssl"]:
            dav_server = WSGIServer(
                server_args["bind_addr"],
                app,
                keyfile=info["ssl_pk"],
                certfile=info["ssl_cert"],
                ca_certs=info["ssl_chain"],
            )
        else:
            dav_server = WSGIServer(server_args["bind_addr"], app)
        startup_event = config.get("startup_event")
        if startup_event:
            def _patched_start():
                dav_server.start_accepting = org_start
                org_start()
                _logger.info("gevent is ready")
                startup_event.set()
            org_start = dav_server.start_accepting
            dav_server.start_accepting = _patched_start
        _logger.info(f"Running {version}")
        _logger.info(f"Serving on {info['url']} ...")
        try:
            gevent.spawn(dav_server.serve_forever())
        except KeyboardInterrupt:
            _logger.warning("Caught Ctrl-C, shutting down...")
        return

    def _run_gunicorn(self, app, config, server):
        try:
            import gunicorn.app.base
        except ImportError:
            _logger.exception("Could not import Gunicorn (https://gunicorn.org).")
            _logger.error("Try `pip install gunicorn` (UNIX only).")
            return False
        info = self._get_common_info(config)
        class GunicornApplication(gunicorn.app.base.BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()

            def load_config(self):
                config = {
                    key: value
                    for key, value in self.options.items()
                    if key in self.cfg.settings and value is not None
                }
                for key, value in config.items():
                    self.cfg.set(key.lower(), value)

            def load(self):
                return self.application
        server_args = {
            "bind": "{}:{}".format(config["host"], config["port"]),
            "threads": 50,
            "timeout": 1200,
        }
        if info["use_ssl"]:
            server_args.update(
                {
                    "keyfile": info["ssl_pk"],
                    "certfile": info["ssl_cert"],
                    "ca_certs": info["ssl_chain"],
                }
            )
        custom_args = util.get_dict_value(config, "server_args", as_dict=True)
        server_args.update(custom_args)

        version = f"gunicorn/{gunicorn.__version__}"
        version = f"WsgiDAV/{__version__} {version} Python {util.PYTHON_VERSION}"
        _logger.info(f"Running {version} ...")
        GunicornApplication(app, server_args).run()

    def _run_paste(self, app, config, server):
        try:
            from paste import httpserver
        except ImportError:
            _logger.exception(
                "Could not import paste.httpserver (https://github.com/cdent/paste)."
            )
            _logger.error("Try `pip install paste`.")
            return False
        info = self._get_common_info(config)
        version = httpserver.WSGIHandler.server_version
        version = f"WsgiDAV/{__version__} {version} Python {util.PYTHON_VERSION}"
        server = httpserver.serve(
            app,
            host=config["host"],
            port=config["port"],
            server_version=version,
            protocol_version="HTTP/1.1",
            start_loop=False,
        )
        if config["verbose"] >= 5:
            __handle_one_request = server.RequestHandlerClass.handle_one_request
            def handle_one_request(self):
                __handle_one_request(self)
                if self.close_connection == 1:
                    _logger.debug("HTTP Connection : close")
                else:
                    _logger.debug("HTTP Connection : continue")
            server.RequestHandlerClass.handle_one_request = handle_one_request
        _logger.info(f"Running {version} ...")
        host, port = server.server_address
        if host == "0.0.0.0":
            _logger.info(f"Serving on 0.0.0.0:{port} view at http://127.0.0.1:{port}")
        else:
            _logger.info(f"Serving on {info['url']}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            _logger.warning("Caught Ctrl-C, shutting down...")
        return

    def _run_uvicorn(self, app, config, server):
        try:
            import uvicorn
        except ImportError:
            _logger.exception("Could not import Uvicorn (https://www.uvicorn.org).")
            _logger.error("Try `pip install uvicorn`.")
            return False
        info = self._get_common_info(config)
        server_args = {
            "interface": "wsgi",
            "host": config["host"],
            "port": config["port"],
        }
        if info["use_ssl"]:
            server_args.update(
                {
                    "ssl_keyfile": info["ssl_pk"],
                    "ssl_certfile": info["ssl_cert"],
                    "ssl_ca_certs": info["ssl_chain"],
                }
            )
        custom_args = util.get_dict_value(config, "server_args", as_dict=True)
        server_args.update(custom_args)
        version = f"uvicorn/{uvicorn.__version__}"
        version = f"WsgiDAV/{__version__} {version} Python {util.PYTHON_VERSION}"
        _logger.info(f"Running {version} ...")
        uvicorn.run(app, **server_args)

    def _run_wsgiref(self, app, config, _server):
        from wsgiref.simple_server import WSGIRequestHandler, make_server

        version = WSGIRequestHandler.server_version
        version = f"WsgiDAV/{__version__} {version}"
        _logger.info(f"Running {version} ...")

        _logger.warning(
            "WARNING: This single threaded server (wsgiref) is not meant for production."
        )
        WSGIRequestHandler.server_version = version
        httpd = make_server(config["host"], config["port"], app)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            _logger.warning("Caught Ctrl-C, shutting down...")
        return

    def run(self):
        SUPPORTED_SERVERS = {
            "cheroot": self._run_cheroot,
            "ext-wsgiutils": self._run_ext_wsgiutils,
            "gevent": self._run_gevent,
            "gunicorn": self._run_gunicorn,
            "paste": self._run_paste,
            "uvicorn": self._run_uvicorn,
            "wsgiref": self._run_wsgiref,
        }
        cli_opts, config = self._init_config()
        util.init_logging(config)
        app = WsgiDAVApp(config)

        server = config["server"]
        handler = SUPPORTED_SERVERS.get(server)
        if not handler:
            raise RuntimeError(
                "Unsupported server type {!r} (expected {!r})".format(
                    server, "', '".join(SUPPORTED_SERVERS.keys())
                )
            )
        handler(app=app, config=config, _server=server)
        return

class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setAcceptDrops(True)
        self.setWindowIcon(QIcon(QPixmap(QSize(512, 512)).fromImage(QImage.fromData(QByteArray.fromBase64(b'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')))))

class Ui_Server(object):
    def setupUi(self, Server):
        if not Server.objectName():
            Server.setObjectName("Server")
        Server.resize(409, 391)
        font = QFont()
        font.setFamilies(["Arial"])
        Server.setFont(font)
        Server.setStyleSheet("QWidget{background: #2d2d2d;color: #ededed;}")
        self.servLabel = QLabel(Server)
        self.servLabel.setObjectName("servLabel")
        self.servLabel.setGeometry(QRect(10, 20, 391, 91))
        font1 = QFont()
        font1.setFamilies(["Arial"])
        font1.setPointSize(30)
        self.servLabel.setFont(font1)
        self.servLabel.setStyleSheet("QLabel{background: #2d2d2d;color: #ededed;}")
        self.servLabel.setAlignment(Qt.AlignCenter)
        self.server_button = QPushButton(Server)
        self.server_button.setObjectName("server_buton")
        self.server_button.setGeometry(QRect(10, 300, 391, 81))
        self.server_button.setFont(font1)
        self.server_button.setStyleSheet("QPushButton{background: #2d2d2d;color: #ededed;border:1px solid #ededed;}\n"
"QPushButton:checked {color: White;background: Red;}")
        self.server_button.setText('サーバー起動')
        self.server_button.clicked.connect(self.ClickedEvent)
        self.server_button.setCheckable(True)
        self.server_button.setChecked(False)
        self.InputPath = QLineEdit(Server)
        self.InputPath.setObjectName("InputPath")
        self.InputPath.setGeometry(QRect(10, 240, 391, 51))
        font2 = QFont()
        font2.setFamilies(["Arial"])
        font2.setPointSize(25)
        self.InputPath.setFont(font2)
        self.InputPath.setStyleSheet("QLineEdit{color: White;background: #131519;border: 2px solid red;}")
        self.iPAdress = QLabel(Server)
        self.iPAdress.setObjectName("iPAdress")
        self.iPAdress.setGeometry(QRect(160, 130, 241, 91))
        font3 = QFont()
        font3.setFamilies(["Arial"])
        font3.setPointSize(17)
        self.iPAdress.setFont(font3)
        self.iPAdress.setStyleSheet("QLabel{background: #2d2d2d;color: #ededed;}")
        self.iPAdress.setAlignment(Qt.AlignCenter)
        self.iPAdress_Label = QLabel(Server)
        self.iPAdress_Label.setObjectName("iPAdress_Label")
        self.iPAdress_Label.setGeometry(QRect(10, 130, 171, 91))
        font3 = QFont()
        font3.setFamilies(["Arial"])
        font3.setPointSize(23)
        self.iPAdress_Label.setFont(font3)
        self.iPAdress_Label.setStyleSheet("QLabel{background: #2d2d2d;color: #ededed;}")
        self.iPAdress_Label.setAlignment(Qt.AlignCenter)

        self.retranslateUi(Server)

        QMetaObject.connectSlotsByName(Server)

    def ClickedEvent(self, c):
        if self.server_button.isChecked():
            self.StartServ()
        else:
            self.StopServ()

    def StopServ(self):
        self.server_button.setText('サーバーを起動')
        self.iPAdress.setText('---.---.---.---:8080')
        self.ServerProcess.terminate()
        self.ServerProcess.kill()

    def StartServ(self):
        self.server_button.setText('サーバーを停止')
        self.iPAdress.setText('{}:8080'.format([ip.toString() for ip in QHostInfo().fromName(QHostInfo().localHostName()).addresses() if ip.toString().count('.') == 3][0]))
        self.ServerClass = WebDAV(running_path=self.InputPath.text().replace(os.sep, '/'))
        self.ServerProcess = multiprocessing.Process(target=self.ServerClass.run, daemon=True)
        self.ServerProcess.start()

    def retranslateUi(self, Server):
        Server.setWindowTitle("簡易サーバー")
        self.servLabel.setText("簡易サーバーツール")
        self.InputPath.setToolTip("<html><head/><body><p>共有したいフォルダの場所を入力</p></body></html>")
        self.InputPath.setPlaceholderText("共有場所のパス")
        self.iPAdress_Label.setText('iPアドレス:')
        self.iPAdress.setText('---.---.---.---:8080')

def main():
    app = QApplication(sys.argv)
    Translator = QTranslator()
    Translator.load('qt_{}'.format(QLocale().system().name()), '{}/Lang'.format(os.getcwd()))
    app.installTranslator(Translator)
    main_win = MainWindow()
    ui = Ui_Server()
    ui.setupUi(main_win)
    main_win.setFixedSize(main_win.size())
    main_win.setWindowFlags(Qt.WindowStaysOnTopHint)
    main_win.show()
    app.exec()

if __name__ == '__main__':
    if platform.system() == 'Linux':
        multiprocessing.set_start_method('fork')
    else:
        multiprocessing.set_start_method('spawn')
    multiprocessing.freeze_support()
    main()

