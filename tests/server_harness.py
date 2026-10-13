"""An in-process GAIDE-Trace server for HTTP-level tests.

Binds 127.0.0.1 on an ephemeral port with a throwaway data directory — never
a network, never a real store (tests/README.md).
"""

import http.client
import json
import shutil
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from fixtures import REPO, load_server

server = load_server()

# PBKDF2 at 600k iterations costs ~0.4 s per hash; computing one per test user
# per test made the suite crawl. Password login is not what these tests cover.
_PASSWORD_HASH, _PASSWORD_SALT = server.hash_password("test-password")


class QuietHandler(server.Handler):
    def log_message(self, fmt, *args):
        pass


class ServerHarness:
    """Owns one server + data dir, plus a credential for every role."""

    def __init__(self):
        self.data_dir = Path(tempfile.mkdtemp(prefix="gaide-trace-test-"))
        self.store = server.Store(self.data_dir)
        QuietHandler.store = self.store
        QuietHandler.webui_dir = REPO / "server" / "webui"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.httpd.daemon_threads = True
        # The default 0.5 s shutdown poll would add half a second to every test.
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

        self.tokens = {
            "admin_user": self.add_user("root", "admin"),
            "member_user": self.add_user("mia", "member"),
            "admin_key": server.create_key(self.store, "admin-script", "admin"),
            "member_key": server.create_key(self.store, "member-script", "member"),
            "agent_key": server.create_key(self.store, "project:p", "agent"),
        }

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def add_user(self, username, role, projects=None):
        """Create a console user and return a signed-in session token.

        `projects=None` gives the *all projects* scope (what every account had
        before specs/project-access); a list, even empty, is an explicit
        scope. Written straight to the index so tests of the scope endpoint
        do not depend on the endpoint under test."""
        with self.store.connect() as db:
            cur = db.execute(
                """INSERT INTO users (username, password_hash, salt, role,
                                      must_change_password, created_at, all_projects)
                   VALUES (?,?,?,?,0,?,?)""",
                (username, _PASSWORD_HASH, _PASSWORD_SALT, role, server.utcnow(),
                 1 if projects is None else 0))
            for name in projects or []:
                db.execute(
                    """INSERT INTO user_projects (user_id, project, granted_at, granted_by)
                       VALUES (?,?,?,?)""",
                    (cur.lastrowid, name, server.utcnow(), "harness"))
            db.commit()
        return server.open_web_session(self.store, cur.lastrowid)

    def raw_request(self, method, path, token=None, data=None,
                    content_type="application/json"):
        """Returns (status, response bytes). Always the local test server."""
        headers = {}
        if data is not None:
            headers["Content-Type"] = content_type
        if token:
            headers["Authorization"] = "Bearer " + token
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def request(self, method, path, token=None, body=None):
        """Returns (status, parsed JSON body)."""
        data = json.dumps(body).encode("utf-8") if body is not None else None
        status, raw = self.raw_request(method, path, token, data)
        try:
            return status, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return status, raw.decode("utf-8", "replace")

    def as_role(self, role, method, path, body=None):
        return self.request(method, path, token=self.tokens[role], body=body)

    def put_transcript(self, session_id, data: bytes, project="p"):
        status, _ = self.raw_request(
            "PUT", f"/api/v1/transcripts/{session_id}?project={project}",
            self.tokens["agent_key"], data, content_type="application/x-ndjson")
        return status

    def post_events(self, records):
        return self.as_role("agent_key", "POST", "/api/v1/events", body=records)
