import os
import sys
import subprocess
import threading
import logging
import argparse
import time
from flask import Flask, Response

# ---- Kleuren voor logging ----
class LogColors:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    PURPLE = "\033[35m"
    RESET = "\033[0m"

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        color = LogColors.RESET
        if record.levelno >= logging.ERROR:
            color = LogColors.RED
        elif record.levelno == logging.WARNING:
            color = LogColors.YELLOW
        elif record.levelno == logging.INFO:
            text = record.getMessage().lower()
            if any(k in text for k in ("request", "get", "post", "put", "delete", "access", "http")):
                color = LogColors.PURPLE
            else:
                color = LogColors.GREEN
        return f"{color}{msg}{LogColors.RESET}"

def setup_logging(level=logging.INFO):
    logger = logging.getLogger()
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    formatter = ColoredFormatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.handlers.clear()
    logger.addHandler(handler)

# ---- Fallback HTML pagina met retro blauwe modemstijl ----
fallback_html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Server couldn't connect</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
<style>
    html, body {
        margin: 0; padding: 0;
        height: 100vh;
        background: linear-gradient(to bottom, #001f3f, #0074D9);
        color: white;
        font-family: "Courier New", Courier, monospace;
        display: flex;
        justify-content: center;
        align-items: center;
        flex-direction: column;
        user-select: none;
        -webkit-user-select: none;
    }
    h1 {
        font-size: 3em;
        margin-bottom: 0.5em;
        text-shadow: 1px 1px 2px black;
    }
    p {
        font-size: 1.2em;
        text-shadow: 1px 1px 2px black;
    }
    ::selection { background: transparent; }
</style>
</head>
<body>
    <h1>Server couldn't connect</h1>
    <p>The requested application is currently unavailable.</p>
</body>
</html>"""

# ---- Fallback Flask server zonder logs ----
def start_fallback_server(port):
    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def fallback(path):
        return Response(fallback_html, status=503, mimetype="text/html")

    # Disable werkzeug logs & flask logs
    log = logging.getLogger('werkzeug')
    log.disabled = True
    app.logger.disabled = True

    # Silence stdout/stderr for this server to avoid log spam
    import warnings
    warnings.filterwarnings("ignore")
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# ---- Gunicorn runner class ----
class GunicornRunner:
    def __init__(self, app_module, ports=None, workers=4, extra_args=None, restart=True):
        self.app_module = app_module
        self.ports = ports or [8000]
        self.workers = workers
        self.extra_args = extra_args or []
        self.restart = restart
        self.processes = {}
        self.stop_flag = False
        self.cwd = os.path.dirname(os.path.abspath(__file__))

    def start_process(self, port):
        if port in self.processes and self.processes[port].poll() is None:
            logging.warning(f"Gunicorn already running on port {port} (PID {self.processes[port].pid})")
            return

        cmd = [
            "gunicorn",
            "-w", str(self.workers),
            "-b", f"0.0.0.0:{port}",
            "--preload",
            "--access-logfile", "-",
            "--error-logfile", "-",
            self.app_module
        ] + self.extra_args

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["FLASK_ENV"] = env.get("FLASK_ENV", "production")

        logging.info(f"Starting Gunicorn on port {port}: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.cwd)

        self.processes[port] = proc

        threading.Thread(target=self._stream_reader, args=(proc.stdout, port, 'stdout'), daemon=True).start()
        threading.Thread(target=self._stream_reader, args=(proc.stderr, port, 'stderr'), daemon=True).start()

    def _stream_reader(self, stream, port, stream_name):
        for line in iter(stream.readline, b''):
            try:
                text = line.decode('utf-8', errors='replace').rstrip()
                level = logging.INFO
                msg_lower = text.lower()

                if any(err in msg_lower for err in ['error', 'fail', 'traceback']):
                    level = logging.ERROR
                elif any(warn in msg_lower for warn in ['warn', 'warning']):
                    level = logging.WARNING
                if any(req in msg_lower for req in ("request", "get", "post", "put", "delete", "access", "http")):
                    level = logging.INFO

                logging.log(level, f"[Gunicorn:{port}][{stream_name}] {text}")

                # Auto-kill bij 500 errors in stderr
                if stream_name == "stderr" and "500 internal server error" in msg_lower:
                    logging.error(f"Detected 500 Internal Server Error on port {port}, killing Gunicorn!")
                    self.kill_all_and_exit()

            except Exception as e:
                logging.error(f"Error reading {stream_name} for port {port}: {e}")
        stream.close()

    def kill_all_and_exit(self):
        logging.error("Killing all Gunicorn processes due to error or crash...")
        self.stop_flag = True
        self.stop_all()
        sys.exit(1)

    def stop_process(self, port):
        proc = self.processes.get(port)
        if proc and proc.poll() is None:
            logging.info(f"Stopping Gunicorn on port {port} (PID {proc.pid})")
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logging.warning(f"Force killing Gunicorn on port {port} (PID {proc.pid})")
                proc.kill()
            del self.processes[port]

    def stop_all(self):
        for port in list(self.processes.keys()):
            self.stop_process(port)

    def monitor(self):
        try:
            while not self.stop_flag:
                for port, proc in list(self.processes.items()):
                    ret = proc.poll()
                    if ret is not None:
                        logging.warning(f"Gunicorn on port {port} exited with code {ret}")
                        del self.processes[port]

                        if self.restart and not self.stop_flag:
                            logging.info(f"Restarting Gunicorn on port {port}")
                            self.start_process(port)
                        else:
                            logging.error(f"Gunicorn on port {port} stopped and restart disabled, exiting...")
                            self.kill_all_and_exit()
                time.sleep(2)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt received, shutting down...")
            self.stop_all()

    def run(self):
        for port in self.ports:
            self.start_process(port)
        self.monitor()

# ---- Check of bestand bestaat (app.py) ----
def app_file_exists(module_name):
    filename = module_name.split(":")[0] + ".py"
    return os.path.isfile(filename)

# ---- Main ----
def main():
    parser = argparse.ArgumentParser(description="Gunicorn runner with fallback server and colored logs")
    parser.add_argument("app_module", nargs='?', default="app:app", help="Flask app module (e.g. app:app)")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[8000], help="Ports to run on")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Number of Gunicorn workers")
    parser.add_argument("--extra-args", nargs="*", default=[], help="Extra gunicorn args")
    parser.add_argument("--no-restart", action="store_true", help="Disable automatic restart")
    parser.add_argument("--loglevel", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    args = parser.parse_args()

    setup_logging(getattr(logging, args.loglevel))

    if not app_file_exists(args.app_module):
        logging.warning(f"App file for module '{args.app_module}' not found, starting fallback server")
        start_fallback_server(args.ports[0])
    else:
        runner = GunicornRunner(
            app_module=args.app_module,
            ports=args.ports,
            workers=args.workers,
            extra_args=args.extra_args,
            restart=not args.no_restart
        )
        runner.run()

if __name__ == "__main__":
    main()