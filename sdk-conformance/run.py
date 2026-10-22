#!/usr/bin/env python3
"""Agent SDK conformance harness.

Runs a real `zentinel` binary in front of a fixture echo upstream, with the
agent under test on its filter chain, and checks over plain HTTP that the
agent speaks agent protocol v2: the handshake, the Configure message, header
mutations, a block, request-body inspection, and reconnecting after the agent
restarts. What the agent has to do is specified in README.md next to this
file.

Language neutral: the agent is any command. `{socket}` and `{grpc}` in the
command are replaced with the Unix socket path and the gRPC address the agent
must listen on (also exported as ZENTINEL_AGENT_SOCKET and
ZENTINEL_AGENT_GRPC_ADDRESS).

Python 3.9+, standard library only.
"""

import argparse
import hashlib
import http.client
import http.server
import json
import os
import platform
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import uuid

CHECKS = ["handshake", "configure", "request_header", "response_header", "block", "body", "reconnect"]
PROFILE_CHECKS = {
    "full": CHECKS,
    # The README quick-start agent: adds X-Hello and allows, nothing else.
    "hello": ["handshake", "request_header", "reconnect"],
}

CONFIG_VALUE = "nested-config-ok"
BLOCK_BODY = "blocked-by-agent"
BODY_MARKER = "block-this-body"
RELEASE_URL = "https://github.com/zentinelproxy/zentinel/releases/download/{v}/zentinel-{v}-{p}.tar.gz"

VERBOSE = False


def log(msg):
    print("[conformance] " + msg, flush=True)


def debug(msg):
    if VERBOSE:
        log(msg)


# --------------------------------------------------------------------------
# Zentinel binary
# --------------------------------------------------------------------------


def release_platform():
    system = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    machine = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine().lower()
    )
    if not system or not machine:
        sys.exit("no zentinel release for %s/%s; pass --zentinel-bin" % (platform.system(), platform.machine()))
    return "%s-%s" % (system, machine)


def fetch_zentinel(url, cache_dir):
    os.makedirs(cache_dir, exist_ok=True)
    key = hashlib.sha256(url.encode()).hexdigest()[:16]
    dest = os.path.join(cache_dir, key)
    binary = os.path.join(dest, "zentinel")
    if os.path.exists(binary):
        return binary
    log("downloading " + url)
    archive = os.path.join(cache_dir, key + ".tar.gz")
    urllib.request.urlretrieve(url, archive)
    try:
        with urllib.request.urlopen(url + ".sha256") as resp:
            expected = resp.read().decode().split()[0]
        with open(archive, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != expected:
            sys.exit("checksum mismatch for %s: %s != %s" % (url, actual, expected))
    except urllib.error.HTTPError:
        log("no .sha256 next to the archive; not verified")
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(archive) as tar:
        member = next((m for m in tar.getmembers() if os.path.basename(m.name) == "zentinel"), None)
        if member is None:
            sys.exit("%s has no zentinel binary" % url)
        member.name = "zentinel"
        tar.extract(member, dest)
    os.chmod(binary, 0o755)
    return binary


def resolve_zentinel(args):
    if args.zentinel_bin:
        return os.path.abspath(args.zentinel_bin)
    url = args.zentinel_url
    if not url and args.zentinel_version:
        url = RELEASE_URL.format(v=args.zentinel_version, p=release_platform())
    if not url:
        sys.exit("pass --zentinel-bin, --zentinel-version or --zentinel-url (or set ZENTINEL_BIN)")
    return fetch_zentinel(url, args.cache_dir)


# --------------------------------------------------------------------------
# Fixture upstream
# --------------------------------------------------------------------------


class Upstream:
    """An HTTP server that records every request and echoes it as JSON."""

    def __init__(self):
        self.seen = {}
        self.lock = threading.Lock()
        upstream = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def handle_any(self):
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                record = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body.decode("utf-8", "replace"),
                }
                with upstream.lock:
                    upstream.seen[self.path] = record
                out = json.dumps(record).encode()
                try:
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                except (BrokenPipeError, ConnectionResetError):
                    # The proxy drops the upstream request of a body-blocked
                    # request; nothing is waiting for this answer.
                    pass

            do_GET = do_POST = do_PUT = handle_any

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def get(self, path):
        with self.lock:
            return self.seen.get(path)

    def close(self):
        self.server.shutdown()


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Process:
    def __init__(self, name, argv_or_cmd, log_path, env=None, shell=False):
        self.name = name
        self.log_path = log_path
        self.log_file = open(log_path, "ab")
        self.proc = subprocess.Popen(
            argv_or_cmd,
            shell=shell,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,  # its own process group: kill wrappers' children too
        )

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        if self.alive():
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                pass
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            pass
        self.log_file.close()

    def tail(self, lines=40):
        try:
            with open(self.log_path, "rb") as f:
                return "\n".join(f.read().decode("utf-8", "replace").splitlines()[-lines:])
        except OSError:
            return ""


def wait_for(predicate, timeout, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def can_connect_tcp(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def can_connect_unix(path):
    if not os.path.exists(path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------


class Reply:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def __repr__(self):
        return "HTTP %s %r %r" % (self.status, self.headers, self.body[:200])


def request(port, method, path, body=None, timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"connection": "close"}
        data = None
        if body is not None:
            data = body.encode()
            # The proxy inspects only some content types by default
            # (waf.body-inspection.content-types); JSON is one of them.
            headers["content-type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        return Reply(resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read().decode("utf-8", "replace"))
    except (OSError, http.client.HTTPException) as e:
        return Reply(0, {}, "request failed: %s" % e)
    finally:
        conn.close()


def unique(prefix):
    return "%s/%s" % (prefix, uuid.uuid4().hex[:12])


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def kdl_config(port, upstream_port, transport, endpoint, profile):
    if transport == "uds":
        where = 'unix-socket "%s"' % endpoint
    else:
        where = 'grpc "http://%s"' % endpoint
    events = '"request_headers"'
    if profile == "full":
        events = '"request_headers" "request_body" "response_headers"'
    return """
system {
    worker-threads 2
}
listeners {
    listener "http" {
        address "127.0.0.1:%(port)d"
        protocol "http"
    }
}
upstreams {
    upstream "backend" {
        target "127.0.0.1:%(upstream)d"
    }
}
agents {
    agent "sdk-under-test" type="custom" {
        %(where)s
        events %(events)s
        timeout-ms 2000
        failure-mode "closed"
        config {
            greeting "hello-from-the-proxy"
            nested {
                value "%(value)s"
                depth 2
            }
        }
    }
}
filters {
    filter "sdk-under-test" {
        type "agent"
        agent "sdk-under-test"
        failure-mode "closed"
    }
}
waf {
    mode "off"
    body-inspection {
        inspect-request-body #true
    }
}
routes {
    route "all" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "sdk-under-test"
        policies {
            failure-mode "closed"
        }
    }
}
observability {
    metrics {
        enabled #false
    }
}
""" % {
        "port": port,
        "upstream": upstream_port,
        "where": where,
        "events": events,
        "value": CONFIG_VALUE,
    }


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


class Session:
    """One transport: agent + zentinel + upstream, and the checks against them."""

    def __init__(self, args, transport, agent_cmd, zentinel, work):
        self.args = args
        self.transport = transport
        self.agent_cmd = agent_cmd
        self.zentinel = zentinel
        self.work = os.path.join(work, transport)
        os.makedirs(self.work, exist_ok=True)
        self.results = {}
        self.details = {}
        self.agent = None
        self.proxy = None
        self.agent_starts = 0
        if transport == "uds":
            self.endpoint = os.path.join(work, "a-%s.sock" % uuid.uuid4().hex[:6])
        else:
            self.endpoint = "127.0.0.1:%d" % free_port()

    # -- lifecycle ---------------------------------------------------------

    def agent_ready(self):
        if self.transport == "uds":
            return can_connect_unix(self.endpoint)
        return can_connect_tcp(int(self.endpoint.rsplit(":", 1)[1]))

    def start_agent(self):
        self.agent_starts += 1
        cmd = self.agent_cmd.replace("{socket}", self.endpoint).replace("{grpc}", self.endpoint)
        env = dict(os.environ)
        if self.transport == "uds":
            env["ZENTINEL_AGENT_SOCKET"] = self.endpoint
        else:
            env["ZENTINEL_AGENT_GRPC_ADDRESS"] = self.endpoint
        log("%s: starting agent: %s" % (self.transport, cmd))
        self.agent = Process(
            "agent", cmd, os.path.join(self.work, "agent-%d.log" % self.agent_starts), env=env, shell=True
        )
        if not wait_for(lambda: self.agent_ready() or not self.agent.alive(), self.args.agent_start_timeout):
            return "the agent did not listen on %s within %ss" % (self.endpoint, self.args.agent_start_timeout)
        if not self.agent.alive():
            return "the agent exited (code %s) before listening" % self.agent.proc.returncode
        return None

    def stop_agent(self):
        if self.agent:
            self.agent.stop()
            self.agent = None
        if self.transport == "uds" and os.path.exists(self.endpoint):
            # A stale socket file would make the restarted agent's readiness
            # check pass before it is listening.
            os.unlink(self.endpoint)

    def start_proxy(self, upstream):
        self.port = free_port()
        path = os.path.join(self.work, "zentinel.kdl")
        with open(path, "w") as f:
            f.write(kdl_config(self.port, upstream.port, self.transport, self.endpoint, self.args.profile))
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "info")
        env.setdefault("NO_COLOR", "1")
        self.proxy = Process("zentinel", [self.zentinel, "-c", path], os.path.join(self.work, "zentinel.log"), env=env)
        return wait_for(lambda: can_connect_tcp(self.port) or not self.proxy.alive(), self.args.proxy_start_timeout) and self.proxy.alive()

    def close(self):
        self.stop_agent()
        if self.proxy:
            self.proxy.stop()

    # -- helpers -------------------------------------------------------------

    def record(self, name, ok, detail):
        if name not in PROFILE_CHECKS[self.args.profile]:
            return
        self.results[name] = "pass" if ok else "FAIL"
        self.details[name] = detail
        log("%s: %-15s %s  %s" % (self.transport, name, "pass" if ok else "FAIL", detail))

    def wait_served(self, timeout):
        """Wait until a request goes through the agent to the upstream."""
        last = [None]

        def served():
            path = unique("/probe")
            reply = request(self.port, "GET", path)
            last[0] = reply
            return reply.status == 200 and self.upstream.get(path) is not None

        ok = wait_for(served, timeout, interval=0.25)
        return ok, last[0]

    # -- the checks ----------------------------------------------------------

    def run(self, upstream):
        self.upstream = upstream
        err = self.start_agent()
        if err:
            self.record("handshake", False, err)
            return self.finish()
        if not self.start_proxy(upstream):
            self.record("handshake", False, "zentinel did not start listening within %ss (a stuck handshake hangs startup, zentinel#599)" % self.args.proxy_start_timeout)
            return self.finish()

        ok, last = self.wait_served(self.args.handshake_timeout)
        self.record(
            "handshake",
            ok,
            "requests through the agent reach the upstream" if ok else "never served through the agent; last reply %r" % last,
        )
        if not ok:
            return self.finish()

        self.check_headers()
        if self.args.profile == "full":
            self.check_block()
            self.check_body()
        self.check_reconnect()
        return self.finish()

    def check_headers(self):
        path = unique("/headers")
        reply = request(self.port, "GET", path)
        seen = self.upstream.get(path)
        headers = (seen or {}).get("headers", {})

        hello = headers.get("x-hello")
        self.record(
            "request_header",
            hello == "from-agent",
            "upstream got X-Hello: %r" % hello,
        )
        if self.args.profile != "full":
            return
        got = headers.get("x-conformance-config")
        self.record(
            "configure",
            got == CONFIG_VALUE,
            "upstream got X-Conformance-Config: %r (want %r, from config.nested.value)" % (got, CONFIG_VALUE),
        )
        resp = reply.headers.get("x-conformance-response")
        self.record(
            "response_header",
            reply.status == 200 and resp == "from-agent",
            "client got HTTP %s with X-Conformance-Response: %r" % (reply.status, resp),
        )

    def check_block(self):
        path = unique("/block")
        reply = request(self.port, "GET", path)
        reached = self.upstream.get(path) is not None
        self.record(
            "block",
            reply.status == 403 and reply.body == BLOCK_BODY and not reached,
            "HTTP %s body %r, upstream %s" % (reply.status, reply.body[:80], "reached (wrong)" if reached else "not reached"),
        )

    def check_body(self):
        problems = []
        # Large enough to need more than one read on most stacks, small
        # enough to stay well under any default body limit.
        harmless = json.dumps({"note": "harmless", "pad": "x" * 2000})
        path = unique("/body")
        reply = request(self.port, "POST", path, harmless)
        seen = self.upstream.get(path)
        if reply.status != 200 or not seen or seen["body"] != harmless:
            problems.append("allowed body: HTTP %s, upstream body %r" % (reply.status, (seen or {}).get("body", "<not reached>")[:60]))

        payload = json.dumps({"note": "first part, " + BODY_MARKER + ", last part"})
        path = unique("/body")
        reply = request(self.port, "POST", path, payload)
        seen = self.upstream.get(path)
        # The proxy opens the upstream request before the body is inspected,
        # so the upstream may see the headers of a body-blocked request; what
        # must not reach it is the body.
        leaked = seen is not None and BODY_MARKER in seen["body"]
        if seen is not None:
            debug("upstream saw the blocked request: %r" % seen)
        if reply.status != 403 or reply.body != "body-seen:" + payload or leaked:
            problems.append(
                "marked body: HTTP %s body %r, body %s the upstream"
                % (reply.status, reply.body[:80], "reached" if leaked else "did not reach")
            )
        self.record("body", not problems, "; ".join(problems) or "agent saw the body: blocked the marked one, passed the other")

    def check_reconnect(self):
        self.stop_agent()
        # Let the proxy notice the agent is gone.
        down = wait_for(lambda: request(self.port, "GET", unique("/down")).status != 200, 10, interval=0.25)
        err = self.start_agent()
        if err:
            self.record("reconnect", False, "restart: " + err)
            return
        ok, last = self.wait_served(self.args.reconnect_timeout)
        detail = "served again after the agent restarted"
        if ok:
            # Served by the new process, configured again, mutating headers.
            path = unique("/after-restart")
            request(self.port, "GET", path)
            headers = (self.upstream.get(path) or {}).get("headers", {})
            if headers.get("x-hello") != "from-agent":
                ok, detail = False, "served after restart without X-Hello: %r" % headers
            elif self.args.profile == "full" and headers.get("x-conformance-config") != CONFIG_VALUE:
                ok, detail = False, "served after restart unconfigured: X-Conformance-Config %r" % headers.get("x-conformance-config")
        else:
            detail = "not served within %ss of the restart; last reply %r" % (self.args.reconnect_timeout, last)
        if not down:
            detail += " (requests kept succeeding while the agent was down: is it on the filter chain?)"
            ok = False
        self.record("reconnect", ok, detail)

    def finish(self):
        for name in PROFILE_CHECKS[self.args.profile]:
            if name not in self.results:
                self.results[name] = "skip"
                self.details[name] = "not run: an earlier check failed"
        failed = any(v != "pass" for v in self.results.values())
        if failed:
            for proc, label in ((self.agent, "agent"), (self.proxy, "zentinel")):
                if proc:
                    log("%s: last lines of the %s log (%s):\n%s" % (self.transport, label, proc.log_path, proc.tail()))
        return self.results


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    global VERBOSE
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--agent-cmd", help="command that starts the agent on the Unix socket {socket}")
    p.add_argument("--grpc-agent-cmd", help="command that starts the agent on the gRPC address {grpc} (host:port)")
    p.add_argument("--profile", choices=sorted(PROFILE_CHECKS), default="full",
                   help="full: the conformance agent from README.md; hello: the README quick-start agent (X-Hello only)")
    p.add_argument("--zentinel-bin", default=os.environ.get("ZENTINEL_BIN"), help="path to a zentinel binary")
    p.add_argument("--zentinel-version", default=os.environ.get("ZENTINEL_VERSION"),
                   help="release tag to download, e.g. 26.10_8 (must include zentinel#603)")
    p.add_argument("--zentinel-url", default=os.environ.get("ZENTINEL_URL"), help="URL of a release tarball")
    p.add_argument("--cache-dir", default=os.path.join(tempfile.gettempdir(), "zentinel-conformance-cache"))
    p.add_argument("--work-dir", help="where configs, sockets and logs go (default: a new temp dir, kept on failure)")
    p.add_argument("--json-out", help="write results as JSON here")
    p.add_argument("--agent-start-timeout", type=float, default=120, help="seconds (includes compiling, for `go run` and the like)")
    p.add_argument("--proxy-start-timeout", type=float, default=30)
    p.add_argument("--handshake-timeout", type=float, default=30)
    p.add_argument("--reconnect-timeout", type=float, default=45)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    VERBOSE = args.verbose

    transports = []
    if args.agent_cmd:
        transports.append(("uds", args.agent_cmd))
    if args.grpc_agent_cmd:
        transports.append(("grpc", args.grpc_agent_cmd))
    if not transports:
        p.error("pass --agent-cmd and/or --grpc-agent-cmd")

    zentinel = resolve_zentinel(args)
    version = subprocess.run([zentinel, "--version"], capture_output=True, text=True).stdout.strip()
    log("zentinel: %s (%s)" % (zentinel, version or "version unknown"))

    # Unix socket paths are limited to ~104 bytes, so keep the work dir short.
    work = args.work_dir or tempfile.mkdtemp(prefix="zc-")
    os.makedirs(work, exist_ok=True)
    work = os.path.abspath(work)

    results = {}
    upstream = Upstream()
    try:
        for transport, cmd in transports:
            session = Session(args, transport, cmd, zentinel, work)
            try:
                results[transport] = {"results": session.run(upstream), "details": session.details}
            finally:
                session.close()
    finally:
        upstream.close()

    names = PROFILE_CHECKS[args.profile]
    print()
    print("| transport | " + " | ".join(names) + " |")
    print("|---|" + "---|" * len(names))
    for transport, r in results.items():
        print("| %s | %s |" % (transport, " | ".join(r["results"][n] for n in names)))
    print()

    ok = all(v == "pass" for r in results.values() for v in r["results"].values())
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"zentinel": version, "profile": args.profile, "passed": ok, "transports": results}, f, indent=2)
    if ok:
        if not args.work_dir:
            shutil.rmtree(work, ignore_errors=True)
        log("all checks passed")
        return 0
    log("FAILED; logs are in " + work)
    return 1


if __name__ == "__main__":
    sys.exit(main())
