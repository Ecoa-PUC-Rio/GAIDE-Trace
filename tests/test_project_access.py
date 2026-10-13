"""Project access over HTTP — specs/project-access AC1, AC2, AC4–AC21.

One store, three projects (`app`, `api`, `research`) plus an unassigned
session; members `all` (all projects), `two` (`app`, `api`) and `none` (empty
list). AC3 and AC22–AC24 are console behaviour, verified against the running
app; AC25 is documentation.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fixtures import assistant_lines, event, load_server, transcript, usage
from server_harness import ServerHarness

server = load_server()

TS = "2026-10-01T10:00:00.000Z"

# Session id -> project. `s-none` carries no project at all.
SESSIONS = {"s-app": "app", "s-api": "api", "s-research": "research", "s-none": None}


class AccessTestCase(unittest.TestCase):

    def setUp(self):
        self.h = ServerHarness()
        self.tokens = self.h.tokens
        self.tokens["all"] = self.h.add_user("all", "member")
        self.tokens["two"] = self.h.add_user("two", "member", projects=["app", "api"])
        self.tokens["none"] = self.h.add_user("none", "member", projects=[])
        self.seed()

    def tearDown(self):
        self.h.close()

    def seed(self):
        records = []
        for sid, project in SESSIONS.items():
            fields = {"project": project} if project else {}
            records.append(event(sid, "prompt.submit", TS, prompt="hi", **fields))
            records.append(event(sid, "tool.call", TS, tool_name=f"tool-{sid}", **fields))
        status, _ = self.h.post_events(records)
        assert status == 200, status
        for sid in ("s-app", "s-research"):
            self.h.put_transcript(sid, transcript(
                assistant_lines(f"model-{SESSIONS[sid]}", usage(output_tokens=1), TS,
                                session_id=sid)), project=SESSIONS[sid])
        # Registered projects: two with data, one without.
        for name in ("app", "research", "new-thing"):
            status, _ = self.h.as_role("admin_user", "POST", "/api/v1/projects",
                                       {"name": name})
            assert status == 201, (name, status)

    # -- helpers --

    def get(self, who, path):
        return self.h.as_role(who, "GET", path)

    def ok(self, who, path):
        status, body = self.get(who, path)
        self.assertEqual(status, 200, body)
        return body

    def set_scope(self, username, payload, who="admin_user"):
        uid = self.user_id(username)
        return self.h.as_role(who, "PUT", f"/api/v1/users/{uid}/scope", payload)

    def user_id(self, username):
        users = self.ok("admin_user", "/api/v1/users")
        return next(u["id"] for u in users if u["username"] == username)

    def user(self, username):
        users = self.ok("admin_user", "/api/v1/users")
        return next(u for u in users if u["username"] == username)

    def registration_id(self, name):
        rows = self.ok("admin_user", "/api/v1/projects/manage")
        return next(r["id"] for r in rows if r["name"] == name)

    def session_ids(self, who, query=""):
        body = self.ok(who, "/api/v1/sessions" + query)
        return sorted(s["session_id"] for s in body["sessions"]), body["total"]


class ScopeManagement(AccessTestCase):

    def test_ac1_admin_sets_a_list_or_all_projects(self):
        status, body = self.set_scope("all", {"projects": ["app"]})
        self.assertEqual(status, 200, body)
        self.assertEqual((self.user("all")["all_projects"], self.user("all")["projects"]),
                         (False, ["app"]))
        status, body = self.set_scope("all", {"all": True})
        self.assertEqual(status, 200, body)
        self.assertEqual((self.user("all")["all_projects"], self.user("all")["projects"]),
                         (True, []))

    def test_ac2_users_listing_reports_every_scope(self):
        by_name = {u["username"]: u for u in self.ok("admin_user", "/api/v1/users")}
        self.assertEqual((by_name["root"]["all_projects"], by_name["root"]["projects"]),
                         (True, []))
        self.assertEqual((by_name["two"]["all_projects"], by_name["two"]["projects"]),
                         (False, ["api", "app"]))
        self.assertEqual((by_name["none"]["all_projects"], by_name["none"]["projects"]),
                         (False, []))

    def test_ac4_names_follow_the_registration_rule(self):
        status, body = self.set_scope("two", {"projects": ["app", "not valid!"]})
        self.assertEqual(status, 400, body)
        self.assertEqual(self.user("two")["projects"], ["api", "app"])  # untouched
        status, body = self.set_scope("two", {"projects": ["never-seen.1_x"]})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.user("two")["projects"], ["never-seen.1_x"])
        for bad in ({"projects": "app"}, {"projects": [1]}, {}, {"all": False},
                    {"projects": [f"p{i}" for i in range(server.MAX_SCOPE_NAMES + 1)]}):
            status, _ = self.set_scope("two", bad)
            self.assertEqual(status, 400, str(bad)[:60])
        self.assertEqual(self.user("two")["projects"], ["never-seen.1_x"])

    def test_ac5_admins_cannot_be_narrowed(self):
        status, body = self.set_scope("root", {"projects": ["app"]})
        self.assertEqual(status, 400, body)
        self.assertTrue(self.user("root")["all_projects"])

    def test_ac6_new_accounts_start_with_an_empty_list(self):
        status, body = self.h.as_role("admin_user", "POST", "/api/v1/users",
                                      {"username": "fresh"})
        self.assertEqual(status, 201, body)
        self.assertEqual((self.user("fresh")["all_projects"], self.user("fresh")["projects"]),
                         (False, []))
        status, body = self.h.as_role("admin_user", "POST", "/api/v1/users",
                                      {"username": "picked", "projects": ["api"]})
        self.assertEqual(status, 201, body)
        self.assertEqual(self.user("picked")["projects"], ["api"])
        status, body = self.h.as_role("admin_user", "POST", "/api/v1/users",
                                      {"username": "wide", "all": True})
        self.assertEqual(status, 201, body)
        self.assertTrue(self.user("wide")["all_projects"])

    def test_ac7_change_applies_to_the_live_token(self):
        self.assertEqual(self.ok("two", "/api/v1/projects"), ["api", "app"])
        status, _ = self.set_scope("two", {"projects": ["app", "api", "research"]})
        self.assertEqual(status, 200)
        self.assertEqual(self.ok("two", "/api/v1/projects"), ["api", "app", "research"])
        status, _ = self.set_scope("two", {"projects": []})
        self.assertEqual(self.ok("two", "/api/v1/projects"), [])

    def test_ac8_me_reports_the_scope(self):
        self.assertIsNone(self.ok("admin_user", "/api/v1/me")["scope"])
        self.assertIsNone(self.ok("all", "/api/v1/me")["scope"])
        self.assertIsNone(self.ok("member_key", "/api/v1/me")["scope"])
        self.assertEqual(self.ok("two", "/api/v1/me")["scope"], ["api", "app"])
        self.assertEqual(self.ok("none", "/api/v1/me")["scope"], [])

    def test_ac9_registering_grants_the_new_project_to_a_scoped_member(self):
        status, body = self.h.as_role("two", "POST", "/api/v1/projects", {"name": "web"})
        self.assertEqual(status, 201, body)
        self.assertEqual(self.user("two")["projects"], ["api", "app", "web"])
        # An existing registration is a 409 and never a grant.
        status, body = self.h.as_role("two", "POST", "/api/v1/projects",
                                      {"name": "research"})
        self.assertEqual(status, 409, body)
        self.assertEqual(self.user("two")["projects"], ["api", "app", "web"])
        # All-projects accounts stay all-projects.
        status, _ = self.h.as_role("all", "POST", "/api/v1/projects", {"name": "other"})
        self.assertEqual(status, 201)
        self.assertEqual((self.user("all")["all_projects"], self.user("all")["projects"]),
                         (True, []))

    def test_ac9_registering_a_name_that_has_data_never_grants_it(self):
        """A seen-but-unregistered project, and one whose registration an
        admin removed, must not be claimable by a scoped member."""
        self.assertEqual(self.user("none")["projects"], [])
        status, body = self.h.as_role("none", "POST", "/api/v1/projects", {"name": "api"})
        self.assertEqual(status, 409, body)
        self.assertEqual(self.user("none")["projects"], [])
        self.assertEqual(self.session_ids("none"), ([], 0))
        research = self.registration_id("research")
        status, _ = self.h.as_role("admin_user", "DELETE", f"/api/v1/projects/{research}")
        self.assertEqual(status, 200)
        status, body = self.h.as_role("none", "POST", "/api/v1/projects",
                                      {"name": "research"})
        self.assertEqual(status, 409, body)
        self.assertEqual(self.user("none")["projects"], [])
        self.assertEqual(self.get("none", "/api/v1/sessions/s-research")[0], 404)
        # An all-projects account may still register a seen project (that is
        # how data arriving through a raw agent key gets its own key).
        status, body = self.h.as_role("all", "POST", "/api/v1/projects",
                                      {"name": "research"})
        self.assertEqual(status, 201, body)

    def test_a_duplicate_registration_leaves_no_orphan_key(self):
        """Found by the verifier: the 409 path used to commit the ingest key
        it had already inserted."""
        with self.h.store.connect() as db:
            before = db.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        for who in ("all", "member_key", "admin_user"):
            status, _ = self.h.as_role(who, "POST", "/api/v1/projects", {"name": "app"})
            self.assertEqual(status, 409, who)
        with self.h.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM keys").fetchone()[0], before)

    def test_ac9_a_member_key_registering_touches_no_grant(self):
        status, body = self.h.as_role("member_key", "POST", "/api/v1/projects",
                                      {"name": "scripted"})
        self.assertEqual(status, 201, body)
        with self.h.store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM user_projects WHERE project = 'scripted'").fetchone()[0], 0)

    def test_ac19_scope_editing_is_admin_only(self):
        for who in ("two", "all", "member_key"):
            status, body = self.set_scope("none", {"all": True}, who=who)
            self.assertEqual(status, 403, (who, body))
        self.assertEqual((self.user("none")["all_projects"], self.user("none")["projects"]),
                         (False, []))


class ScopeSql(unittest.TestCase):
    """The three shapes of the shared read filter (plan: unit tests)."""

    def test_shapes(self):
        self.assertEqual(server.scope_sql({"scope": None}, "project"), ("", []))
        self.assertEqual(server.scope_sql({"scope": []}, "project"), ("0 = 1", []))
        self.assertEqual(server.scope_sql({"scope": ["a", "b"]}, "s.project"),
                         ("s.project IN (?,?)", ["a", "b"]))


class Migration(unittest.TestCase):

    def test_ac6_pre_existing_accounts_keep_all_projects(self):
        """A v0.5 store: the users table has no all_projects column."""
        data_dir = Path(tempfile.mkdtemp(prefix="gaide-trace-migrate-"))
        db = sqlite3.connect(data_dir / "trace.db")
        db.executescript("""
            CREATE TABLE users (
              id INTEGER PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              salt TEXT NOT NULL,
              role TEXT NOT NULL CHECK (role IN ('member','admin')),
              must_change_password INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              last_login_at TEXT,
              disabled_at TEXT
            );
            INSERT INTO users (username, password_hash, salt, role, created_at)
              VALUES ('old-member', 'x', 'y', 'member', '2026-01-01T00:00:00Z'),
                     ('old-admin', 'x', 'y', 'admin', '2026-01-01T00:00:00Z');
        """)
        db.commit()
        db.close()
        store = server.Store(data_dir)
        with store.connect() as db:
            rows = {r["username"]: r["all_projects"]
                    for r in db.execute("SELECT username, all_projects FROM users")}
        self.assertEqual(rows, {"old-member": 1, "old-admin": 1})
        # Running the schema again must not widen an account narrowed since.
        with store.connect() as db:
            db.execute("UPDATE users SET all_projects = 0 WHERE username = 'old-member'")
            db.commit()
        server.Store(data_dir)
        with store.connect() as db:
            self.assertEqual(db.execute(
                "SELECT all_projects FROM users WHERE username = 'old-member'"
            ).fetchone()[0], 0)


class Enforcement(AccessTestCase):

    def test_ac10_project_lists_are_scoped(self):
        self.assertEqual(self.ok("two", "/api/v1/projects"), ["api", "app"])
        self.assertEqual(self.ok("none", "/api/v1/projects"), [])
        self.assertEqual(self.ok("all", "/api/v1/projects"), ["api", "app", "research"])
        manage = lambda who: sorted(r["name"] for r in self.ok(who, "/api/v1/projects/manage"))
        self.assertEqual(manage("two"), ["app"])
        self.assertEqual(manage("none"), [])
        self.assertEqual(manage("all"), ["app", "new-thing", "research"])

    def test_ac11_overview_counts_visible_data_only(self):
        o = self.ok("two", "/api/v1/overview")
        self.assertEqual((o["totals"]["sessions"], o["totals"]["events"],
                          o["totals"]["projects"]), (2, 4, 2))
        self.assertEqual(sorted(p["project"] for p in o["projects"]), ["api", "app"])
        self.assertEqual(sum(p["sessions"] for p in o["origins"]), 2)
        self.assertEqual(sorted(t["tool"] for t in o["top_tools"]),
                         ["tool-s-api", "tool-s-app"])
        self.assertEqual([r["model"] for r in o["models"]["rows"]], ["model-app"])
        self.assertEqual({d["model"] for d in o["models"]["per_day"]}, {"model-app"})
        self.assertEqual(sum(d["prompts"] for d in o["per_day"]), 2)
        empty = self.ok("none", "/api/v1/overview")
        self.assertEqual((empty["totals"]["sessions"], empty["totals"]["events"],
                          empty["projects"], empty["models"]["rows"]), (0, 0, [], []))

    def test_ac12_session_list_is_scoped_and_filters_stay_quiet(self):
        self.assertEqual(self.session_ids("two"), (["s-api", "s-app"], 2))
        self.assertEqual(self.session_ids("two", "?project=research"), ([], 0))
        self.assertEqual(self.session_ids("two", "?project=app"), (["s-app"], 1))
        self.assertEqual(self.session_ids("none"), ([], 0))

    def test_ac13_hidden_session_answers_as_unknown(self):
        ghost = self.get("two", "/api/v1/sessions/does-not-exist")
        hidden = self.get("two", "/api/v1/sessions/s-research")
        self.assertEqual(ghost[0], 404)
        self.assertEqual(hidden, ghost)
        ghost_t = self.h.raw_request("GET", "/api/v1/sessions/does-not-exist/transcript",
                                     self.tokens["two"])
        hidden_t = self.h.raw_request("GET", "/api/v1/sessions/s-research/transcript",
                                      self.tokens["two"])
        self.assertEqual(ghost_t[0], 404)
        self.assertEqual(hidden_t, ghost_t)
        # And the same session is served inside the scope.
        self.assertEqual(self.get("two", "/api/v1/sessions/s-app")[0], 200)
        self.assertEqual(self.h.raw_request("GET", "/api/v1/sessions/s-app/transcript",
                                            self.tokens["two"])[0], 200)

    def test_ac14_export_is_scoped_whatever_the_filters_say(self):
        def export(who, query=""):
            status, raw = self.h.raw_request("GET", "/api/v1/export" + query,
                                             self.tokens[who])
            self.assertEqual(status, 200)
            return raw.decode("utf-8")
        lines = [json.loads(l) for l in export("two", "?format=jsonl").splitlines()]
        self.assertEqual({l["session_id"] for l in lines}, {"s-app", "s-api"})
        self.assertEqual(export("two", "?format=jsonl&project=research"), "")
        self.assertEqual(export("two", "?format=jsonl&session=s-research"), "")
        self.assertEqual(export("two", "?format=jsonl&session=s-none"), "")
        csv_rows = export("two", "?format=csv").splitlines()
        self.assertEqual(len(csv_rows), 1 + 4)  # header + visible events
        self.assertNotIn("research", export("two", "?format=csv"))
        self.assertEqual(export("none", "?format=jsonl"), "")
        all_lines = export("all", "?format=jsonl").splitlines()
        self.assertEqual(len(all_lines), 8)

    def test_ac15_model_list_comes_from_visible_data_plus_priced_models(self):
        status, _ = self.h.as_role("admin_user", "PUT", "/api/v1/models/prices", {
            "model": "model-priced", "input": 1, "output": 1, "cache_read": 1,
            "cache_write_5m": 1, "cache_write_1h": 1})
        self.assertEqual(status, 200)
        listed = {m["model"]: m for m in self.ok("two", "/api/v1/models")["models"]}
        self.assertEqual(set(listed), {"model-app", "model-priced"})
        self.assertEqual(listed["model-app"]["turns"], 1)
        self.assertEqual(set(m["model"] for m in self.ok("none", "/api/v1/models")["models"]),
                         {"model-priced"})
        self.assertEqual(set(m["model"] for m in self.ok("all", "/api/v1/models")["models"]),
                         {"model-app", "model-research", "model-priced"})

    def test_ac16_rotate_is_scoped(self):
        research = self.registration_id("research")
        app = self.registration_id("app")
        ghost = self.h.as_role("two", "POST", "/api/v1/projects/999999/rotate")
        hidden = self.h.as_role("two", "POST", f"/api/v1/projects/{research}/rotate")
        self.assertEqual(ghost[0], 404)
        self.assertEqual(hidden, ghost)
        status, body = self.h.as_role("two", "POST", f"/api/v1/projects/{app}/rotate")
        self.assertEqual(status, 200, body)

    def test_ac17_unassigned_data_is_visible_to_all_projects_only(self):
        self.assertEqual(self.session_ids("all"), (["s-api", "s-app", "s-none", "s-research"], 4))
        self.assertNotIn("s-none", self.session_ids("two")[0])
        self.assertEqual(self.get("two", "/api/v1/sessions/s-none")[0], 404)
        self.assertEqual(self.get("all", "/api/v1/sessions/s-none")[0], 200)

    def test_ac18_admins_and_keys_see_everything(self):
        for who in ("admin_user", "admin_key", "member_key"):
            self.assertEqual(self.session_ids(who)[1], 4, who)
            self.assertEqual(self.ok(who, "/api/v1/projects"), ["api", "app", "research"])
            self.assertEqual(self.ok(who, "/api/v1/overview")["totals"]["events"], 8)

    def test_ac20_no_read_endpoint_names_a_hidden_project(self):
        for path in ("/api/v1/projects", "/api/v1/projects/manage", "/api/v1/overview",
                     "/api/v1/sessions", "/api/v1/models", "/api/v1/me",
                     "/api/v1/sessions?project=research",
                     "/api/v1/sessions/s-research", "/api/v1/export?format=jsonl"):
            status, raw = self.h.raw_request("GET", path, self.tokens["two"])
            self.assertNotIn(b"research", raw, path)
            self.assertNotIn(b"new-thing", raw, path)

    def test_ac21_hidden_and_absent_projects_are_indistinguishable(self):
        for path in ("/api/v1/sessions?project=%s", "/api/v1/overview?project=%s",
                     "/api/v1/export?format=jsonl&project=%s",
                     "/api/v1/export?format=csv&project=%s"):
            hidden = self.h.raw_request("GET", path % "research", self.tokens["two"])
            absent = self.h.raw_request("GET", path % "ghost", self.tokens["two"])
            self.assertEqual(hidden, absent, path)
        # Neither the shipping key's name nor a model used only by a hidden
        # project is an oracle either.
        for path in ("/api/v1/sessions?origin=%s", "/api/v1/export?format=jsonl&origin=%s"):
            hidden = self.h.raw_request("GET", path % "project:p", self.tokens["none"])
            absent = self.h.raw_request("GET", path % "nobody", self.tokens["none"])
            self.assertEqual(hidden, absent, path)
        hidden = self.h.raw_request("GET", "/api/v1/sessions?model=model-research",
                                    self.tokens["two"])
        absent = self.h.raw_request("GET", "/api/v1/sessions?model=model-ghost",
                                    self.tokens["two"])
        self.assertEqual(hidden, absent)


if __name__ == "__main__":
    unittest.main()
