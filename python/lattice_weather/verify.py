"""evidence.verify (§5.3, §6.3): offline bundle verification, Python side."""

import base64

from .canon import J, D, ZERO
from .crypto import verify_detached
from .window import evaluate_results
from .usage import usage_payload_hash

_REASONS_ORDERED = [
    "NO_PAGES", "PARSE_INVALID", "HASH_MISMATCH", "SIGNATURE_INVALID",
    "CHAIN_INVALID", "TRANSITION_INVALID", "OBJECT_MISSING", "OBJECT_CONFLICT",
    "REPLAY_MISMATCH", "PACK_UNAVAILABLE", "HEAD_MISMATCH", "INCOMPLETE",
]


def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _u(x):
    return int(x)


class _Verifier:
    def __init__(self):
        self.reasons = set()
        self.integrity_bad = False
        self.replay_bad = False
        self.incomplete = False
        self.pack_unavailable = False

        self.logical = 0
        self.fleet = ""
        self.configs = {}
        self.active = None
        self.pending_cfg = None
        self.last_scheduled = None
        self.revoked = set()
        self.sources = {}
        self.accepted_list = []
        self.usage_ids = {}
        self.windows = []
        self.results = {}
        self.alerts = {}
        self.subs = {}
        self.outbox = {}
        self.through_idx = 0
        self.objects = {}
        self.referenced = set()
        self.positions = {}
        self.saw_config_scheduled = False
        self.audit_key_id = ""
        self.audit_root_key = ""
        self.root_pub = ""
        self.pw = None

    def fail(self, r):
        self.reasons.add(r)
        if r == "REPLAY_MISMATCH":
            self.replay_bad = True
        elif r == "PACK_UNAVAILABLE":
            self.pack_unavailable = True
            self.incomplete = True
        elif r in ("INCOMPLETE", "HEAD_MISMATCH"):
            self.incomplete = True
        else:
            self.integrity_bad = True

    def sig(self, env, tag, public_key_b64):
        try:
            return verify_detached(_b64(public_key_b64), tag, env["hash"], _b64(env["sig"]))
        except Exception:
            return False

    def event(self, b):
        at = _u(b["at_ms"])
        if self.pw and b["kind"] not in ("ResultFinalized", "AlertCreated"):
            if self.pw["got"] != self.pw["expect"]:
                self.fail("TRANSITION_INVALID")
            self.pw = None
        d = b["data"]
        k = b["kind"]
        if k == "Tick":
            self._tick(d["logical_ms"], at)
        elif k == "ConfigScheduled":
            self._config_scheduled(d["config"])
        elif k == "ConfigActivated":
            self._config_activated(d["config"], at)
        elif k == "KeysRevoked":
            for kk in d["keys"]:
                self.revoked.add(kk)
        elif k == "SourceAccepted":
            self._source_accepted(d["accepted"], at)
        elif k == "SourceBuffered":
            self._source_buffered(d["entry"])
        elif k == "SourceForkObserved":
            self._fork(d["source"], d["left"], d["right"], d["reason"])
        elif k == "WindowFinalized":
            self._window_finalized(d["manifest"], d["result_count"])
        elif k == "ResultFinalized":
            self._result_finalized(d["result"])
        elif k == "AlertCreated":
            self._alert_created(d["alert"])
        elif k == "VoteAccepted":
            self._vote_accepted(d["alert"], d["vote"], at)
        elif k == "AlertChanged":
            self._alert_changed(d["alert"], d["from"], d["to"], d["actor"], d["revision"], at)
        elif k == "AlertDegraded":
            self._alert_degraded(d["alert"], d["source"], d["key"], d["revision"])
        elif k == "SubscriptionChanged":
            self._sub_changed(d["subscription"], d["event"])
        elif k == "DeliveryChanged":
            self._delivery_changed(d["delivery"], d["page"])

    def _tick(self, logical, at):
        l = _u(logical)
        if l != at or l <= self.logical:
            self.fail("TRANSITION_INVALID")
        else:
            self.logical = l

    def _config_scheduled(self, config_hash):
        rec = self.objects.get(f"config:{config_hash}")
        if not rec:
            self.fail("OBJECT_MISSING")
            return
        if rec["key_id"] != self.audit_root_key or not self.sig(rec, "WEATHER-CONFIG-SIGN/1", self.root_pub):
            self.fail("SIGNATURE_INVALID")
            return
        c = rec["body"]
        if c["fleet"] != self.fleet:
            self.fail("TRANSITION_INVALID")
            return
        if not self.saw_config_scheduled:
            if c["epoch"] != "1" or c["predecessor"] != ZERO:
                self.fail("TRANSITION_INVALID")
                return
        else:
            prev = self.active["body"] if self.active else None
            prev_hash = self.active["hash"] if self.active else (self.last_scheduled["hash"] if self.last_scheduled else None)
            if not prev or not prev_hash:
                self.fail("TRANSITION_INVALID")
                return
            if _u(c["epoch"]) != _u(prev["epoch"]) + 1 or c["predecessor"] != prev_hash:
                self.fail("CHAIN_INVALID")
                return
            if self.pending_cfg:
                self.fail("TRANSITION_INVALID")
                return
            old_sources = {s["id"]: s for s in prev["sources"]}
            for s in c["sources"]:
                o = old_sources.get(s["id"])
                if o and (o["principal"] != s["principal"] or o["pin"]["key_id"] != s["pin"]["key_id"]
                          or o["pin"]["public_key"] != s["pin"]["public_key"] or o["profile"] != s["profile"]
                          or o["meter"] != s["meter"] or o["subjects"] != s["subjects"]):
                    self.fail("TRANSITION_INVALID")
                    return
        if c["pack"] != "weather-core/1.0.0":
            self.fail("PACK_UNAVAILABLE")
        self.configs[config_hash] = rec
        self.pending_cfg = rec
        self.saw_config_scheduled = True
        self.last_scheduled = rec
        for k in c["revoked_keys"]:
            self.revoked.add(k)

    def _config_activated(self, config_hash, at):
        if not self.pending_cfg or self.pending_cfg["hash"] != config_hash:
            self.fail("TRANSITION_INVALID")
            return
        if _u(self.pending_cfg["body"]["effective_ms"]) > at:
            self.fail("TRANSITION_INVALID")
            return
        c = self.pending_cfg["body"]
        in_cfg = {s["id"]: s for s in c["sources"]}
        for st in self.sources.values():
            nc = in_cfg.get(st["id"])
            if (not nc or not nc["enabled"]) and st["state"] != "RETIRED":
                st["state"] = "RETIRED"
        for sc in c["sources"]:
            if not sc["enabled"]:
                continue
            if sc["id"] not in self.sources:
                self.sources[sc["id"]] = {
                    "id": sc["id"], "state": "EMPTY", "seq": 0, "hash": ZERO,
                    "activated_ms": c["effective_ms"], "last_ms": None,
                    "last_input": None, "complete": True, "pending": {},
                }
        self.active = self.pending_cfg
        self.pending_cfg = None
        self.windows = []

    def _src_cfg(self, source):
        if not self.active:
            return None
        return next((s for s in self.active["body"]["sources"] if s["id"] == source), None)

    def _entry_sig_ok(self, e):
        if e["hash"] != D("WEATHER-SOURCE/1", e["body"]):
            self.fail("HASH_MISMATCH")
            return False
        if e["body"]["fleet"] != self.fleet:
            self.fail("TRANSITION_INVALID")
            return False
        sc = self._src_cfg(e["body"]["source"])
        if not sc:
            self.fail("TRANSITION_INVALID")
            return False
        if sc["pin"]["key_id"] != e["body"]["key_id"]:
            self.fail("SIGNATURE_INVALID")
            return False
        if not verify_detached(_b64(sc["pin"]["public_key"]), "WEATHER-SOURCE-SIGN/1", e["hash"], _b64(e["sig"])):
            self.fail("SIGNATURE_INVALID")
            return False
        if sc["profile"] != e["body"]["native"]["profile"]:
            self.fail("TRANSITION_INVALID")
            return False
        obs = e["body"]["observation"]
        if "subject" in obs and obs["subject"] not in sc["subjects"]:
            self.fail("TRANSITION_INVALID")
            return False
        if obs["kind"] == "spend" and not sc["meter"]:
            self.fail("TRANSITION_INVALID")
            return False
        if obs["kind"] in ("scope", "replication") and sc["meter"]:
            self.fail("TRANSITION_INVALID")
            return False
        return True

    def _source_accepted(self, a, at):
        st = self.sources.get(a["entry"]["body"]["source"])
        if not self._entry_sig_ok(a["entry"]):
            return
        if not st or st["state"] in ("RETIRED", "TERMINAL", "FORKED"):
            self.fail("TRANSITION_INVALID")
            return
        e = a["entry"]
        seq = _u(e["body"]["seq"])
        if seq != st["seq"] + 1:
            self.fail("CHAIN_INVALID")
            return
        if st["seq"] == 0:
            if e["body"]["prev"] != ZERO:
                self.fail("CHAIN_INVALID")
                return
        elif e["body"]["prev"] != st["hash"]:
            self.fail("CHAIN_INVALID")
            return
        if _u(a["received_ms"]) != at:
            self.fail("TRANSITION_INVALID")
            return
        if _u(a["index"]) != self.through_idx + 1:
            self.fail("CHAIN_INVALID")
            return
        max_late = int(self.active["body"]["max_late_ms"]) if self.active else 120000
        late = _u(e["body"]["observed_ms"]) < at - max_late
        if a["late"] != late:
            self.fail("TRANSITION_INVALID")
            return
        obs = e["body"]["observation"]
        counted = True
        if obs["kind"] == "spend":
            ph = usage_payload_hash(obs["subject"], obs["delta"], obs["unit"])
            smap = self.usage_ids.setdefault(st["id"], {})
            prev_p = smap.get(obs["usage_id"])
            if prev_p is not None:
                if prev_p != ph:
                    self.fail("TRANSITION_INVALID")
                    return
                counted = False
            else:
                smap[obs["usage_id"]] = ph
        if a["counted"] != counted:
            self.fail("TRANSITION_INVALID")
            return
        if obs["kind"] == "terminal" and st["pending"]:
            self.fail("TRANSITION_INVALID")
            return
        st["seq"] = seq
        st["hash"] = e["hash"]
        if obs["kind"] != "signal":
            st["last_ms"] = a["received_ms"]
            st["last_input"] = e["hash"]
        if obs["kind"] == "coverage":
            st["complete"] = obs["complete"]
        st["state"] = "TERMINAL" if obs["kind"] == "terminal" else ("GAPPED" if st["pending"] else "ACTIVE")
        self.through_idx += 1
        self.accepted_list.append(a)

    def _source_buffered(self, e):
        st = self.sources.get(e["body"]["source"])
        if not self._entry_sig_ok(e):
            return
        if not st or st["state"] in ("RETIRED", "TERMINAL", "FORKED"):
            self.fail("TRANSITION_INVALID")
            return
        seq = _u(e["body"]["seq"])
        if seq <= st["seq"] or seq in st["pending"]:
            self.fail("TRANSITION_INVALID")
            return
        st["pending"][seq] = e
        st["state"] = "GAPPED"

    def _fork(self, source, left, right, reason):
        st = self.sources.get(source)
        if not st:
            self.fail("TRANSITION_INVALID")
            return
        for e in (left, right):
            if e["body"]["source"] != source:
                self.fail("TRANSITION_INVALID")
                return
            if not self._entry_sig_ok(e):
                return
        if reason == "SLOT_FORK":
            if _u(left["body"]["seq"]) != _u(right["body"]["seq"]) or left["hash"] == right["hash"]:
                self.fail("TRANSITION_INVALID")
                return
        else:
            terms = [e for e in (left, right) if e["body"]["observation"]["kind"] == "terminal"]
            if len(terms) != 1:
                self.fail("TRANSITION_INVALID")
                return
        st["state"] = "FORKED"

    def _window_finalized(self, manifest_hash, result_count):
        m = self.objects.get(f"manifest:{manifest_hash}")
        if not m or not self.active:
            self.fail("TRANSITION_INVALID" if m else "OBJECT_MISSING")
            return
        wacc = [a for a in self.accepted_list
                if _u(m["start_ms"]) <= _u(a["received_ms"]) < _u(m["end_ms"])]
        closes = sorted(
            (self._close_of(s) for s in self.active["body"]["sources"] if s["enabled"]),
            key=lambda c: c["source"])
        recomputed = {
            "v": 1, "fleet": m["fleet"], "config": m["config"],
            "start_ms": m["start_ms"], "end_ms": m["end_ms"],
            "through_index": str(self.through_idx),
            "inputs": [a["entry"]["hash"] for a in wacc],
            "history": [D("WEATHER-MANIFEST/1", w["manifest"]) for w in self.windows[-5:]],
            "cuts": [{
                "source": c["source"], "head": {"seq": c["head_seq"], "hash": c["head_hash"]},
                "state": c["state"], "activated_ms": c["activated_ms"],
                "last_received_ms": c["last_received_ms"], "last_input": c["last_input"],
                "complete": c["complete"],
            } for c in closes],
            "quality": self._quality(closes, wacc),
        }
        if D("WEATHER-MANIFEST/1", recomputed) != manifest_hash:
            self.fail("REPLAY_MISMATCH")
        win = {
            "fleet": m["fleet"], "config_hash": m["config"], "config": self.active["body"],
            "start_ms": m["start_ms"], "end_ms": m["end_ms"],
            "through_index": str(self.through_idx), "accepted": wacc,
            "history": recomputed["history"], "history_windows": self.windows[-5:],
            "closes": closes, "revoked_keys": set(self.revoked),
        }
        results = evaluate_results(win, recomputed, manifest_hash)
        if len(results) != result_count:
            self.fail("REPLAY_MISMATCH")
            return
        self.pw = {"manifest": recomputed, "expect": result_count, "got": 0, "results": results}
        self.windows.append({"manifest": recomputed, "accepted": wacc})
        if len(self.windows) > 5:
            self.windows.pop(0)

    def _close_of(self, s):
        st = self.sources[s["id"]]
        return {
            "source": s["id"], "head_seq": str(st["seq"]), "head_hash": st["hash"],
            "state": st["state"], "activated_ms": st["activated_ms"],
            "last_received_ms": st["last_ms"], "last_input": st["last_input"],
            "complete": st["complete"], "pending": len(st["pending"]),
            "revoked": s["pin"]["key_id"] in self.revoked,
        }

    @staticmethod
    def _quality(closes, accepted):
        for c in closes:
            if c["state"] == "FORKED" or c["revoked"]:
                return "DEGRADED"
        any_late = any(a["late"] and a["entry"]["body"]["observation"]["kind"] != "signal" for a in accepted)
        for c in closes:
            if c["state"] == "GAPPED" or c["pending"] > 0 or not c["complete"]:
                return "INCOMPLETE"
        return "INCOMPLETE" if any_late else "COMPLETE"

    def _result_finalized(self, result_hash):
        pw = self.pw
        if not pw:
            self.fail("TRANSITION_INVALID")
            return
        rec = self.objects.get(f"result:{result_hash}")
        if not rec:
            self.fail("OBJECT_MISSING")
            return
        exp = pw["results"][pw["got"]] if pw["got"] < len(pw["results"]) else None
        if not exp or rec["hash"] != exp["hash"]:
            self.fail("REPLAY_MISMATCH")
        self.results[result_hash] = rec
        pw["got"] += 1

    def _alert_created(self, alert):
        pw = self.pw
        if not pw:
            self.fail("TRANSITION_INVALID")
            return
        if (alert["state"] != "CANDIDATE" or alert["revision"] != "1" or alert["domains"]
                or alert["votes"] or alert["delivery"] != "NONE" or alert["assurance"] != "VALID"):
            self.fail("TRANSITION_INVALID")
            return
        hit = next((r for r in pw["results"] if r["hash"] == alert["result"]), None)
        if not hit or hit["body"]["decision"]["status"] != "HIT":
            self.fail("TRANSITION_INVALID")
            return
        expect_exp = _u(pw["manifest"]["end_ms"]) + int(self.active["body"]["vote_ttl_ms"])
        if _u(alert["expires_ms"]) != expect_exp:
            self.fail("TRANSITION_INVALID")
            return
        self.alerts[alert["id"]] = {"view": dict(alert), "votes": {}, "domains": set(), "degraded": set()}

    def _vote_accepted(self, alert_id, vote, at):
        al = self.alerts.get(alert_id)
        if not al:
            self.fail("TRANSITION_INVALID")
            return
        if vote["hash"] != D("WEATHER-VOTE/1", vote["body"]):
            self.fail("HASH_MISMATCH")
            return
        res = self.results.get(vote["body"]["result"])
        if not res or res["hash"] != al["view"]["result"]:
            self.fail("TRANSITION_INVALID")
            return
        if (vote["body"]["fleet"] != self.fleet or vote["body"]["config"] != res["body"]["config"]
                or vote["body"]["manifest"] != res["body"]["manifest"]):
            self.fail("TRANSITION_INVALID")
            return
        rcfg = self.configs.get(res["body"]["config"])
        if not rcfg:
            self.fail("OBJECT_MISSING")
            return
        wc = next((w for w in rcfg["body"]["watchers"] if w["id"] == vote["body"]["watcher"]), None)
        if not wc or not wc["enabled"]:
            self.fail("TRANSITION_INVALID")
            return
        if wc["pin"]["key_id"] != vote["body"]["key_id"]:
            self.fail("SIGNATURE_INVALID")
            return
        if not self.sig(vote, "WEATHER-VOTE-SIGN/1", wc["pin"]["public_key"]):
            self.fail("SIGNATURE_INVALID")
            return
        if at >= _u(al["view"]["expires_ms"]):
            self.fail("TRANSITION_INVALID")
            return
        if al["view"]["state"] in ("CLOSED", "EXPIRED"):
            self.fail("TRANSITION_INVALID")
            return
        if vote["body"]["watcher"] in al["votes"]:
            self.fail("TRANSITION_INVALID")
            return
        al["votes"][vote["body"]["watcher"]] = vote["hash"]
        if vote["body"]["key_id"] not in self.revoked:
            al["domains"].add(wc["domain"])
        al["view"]["votes"] = sorted(al["votes"].values())
        al["view"]["domains"] = sorted(al["domains"])
        al["view"]["revision"] = str(_u(al["view"]["revision"]) + 1)

    def _alert_changed(self, alert_id, frm, to, actor, revision, at):
        al = self.alerts.get(alert_id)
        if not al:
            self.fail("TRANSITION_INVALID")
            return
        if al["view"]["state"] != frm or _u(revision) != _u(al["view"]["revision"]) + 1:
            self.fail("TRANSITION_INVALID")
            return
        ok = (
            (frm == "CANDIDATE" and to == "CORROBORATED" and actor is None
             and len(al["domains"]) >= 2 and al["view"]["assurance"] == "VALID")
            or (frm == "CANDIDATE" and to == "EXPIRED" and actor is None
                and at >= _u(al["view"]["expires_ms"]))
            or (frm == "CORROBORATED" and to == "ACKNOWLEDGED" and actor is not None)
            or (frm in ("CANDIDATE", "CORROBORATED", "ACKNOWLEDGED") and to == "CLOSED" and actor is not None)
        )
        if not ok:
            self.fail("TRANSITION_INVALID")
            return
        al["view"]["state"] = to
        al["view"]["revision"] = revision

    def _alert_degraded(self, alert_id, source, key, revision):
        al = self.alerts.get(alert_id)
        if not al or al["view"]["assurance"] != "VALID":
            self.fail("TRANSITION_INVALID")
            return
        if _u(revision) != _u(al["view"]["revision"]) + 1:
            self.fail("TRANSITION_INVALID")
            return
        cause = f"{source or '-'}:{key or '-'}"
        if cause in al["degraded"]:
            self.fail("TRANSITION_INVALID")
            return
        al["degraded"].add(cause)
        al["view"]["assurance"] = "DEGRADED"
        al["view"]["revision"] = revision

    def _sub_changed(self, sub, ev):
        cur = self.subs.get(sub["id"])
        legal = (
            (ev == "OPEN" and not cur and sub["state"] == "ACTIVE")
            or (ev == "PAUSE" and cur and cur["state"] == "ACTIVE" and sub["state"] == "PAUSED")
            or (ev == "RESUME" and cur and cur["state"] == "PAUSED" and sub["state"] == "ACTIVE")
            or (ev == "EXPIRE" and cur and cur["state"] in ("ACTIVE", "PAUSED") and sub["state"] == "EXPIRED")
            or (ev == "CLOSE" and cur and cur["state"] in ("ACTIVE", "PAUSED") and sub["state"] == "CLOSED")
        )
        if not legal:
            self.fail("TRANSITION_INVALID")
            return
        self.subs[sub["id"]] = sub

    def _delivery_changed(self, d, page):
        if page is not None and f"page:{page}" not in self.objects:
            self.fail("OBJECT_MISSING")
            return
        cur = self.outbox.get(d["alert"])
        s = cur["state"] if cur else "NONE"
        legal = (
            (s == "NONE" and d["state"] == "QUEUED" and d["attempts"] == 0)
            or (s in ("QUEUED", "RETRY") and d["state"] in ("IN_FLIGHT", "CANCELLED"))
            or (s == "IN_FLIGHT" and d["state"] in ("DELIVERED", "RETRY", "FAILED", "CANCELLED"))
        )
        if not legal:
            self.fail("TRANSITION_INVALID")
            return
        self.outbox[d["alert"]] = d


def _canon(v):
    return J(v)


def verify(inp):
    V = _Verifier()
    head0 = {"seq": "0", "hash": ZERO}

    if not inp["pages"]:
        return {"integrity": "INVALID", "replay": "INCOMPLETE", "completeness": "INCOMPLETE",
                "native_truth": "NOT_ATTESTED", "head": head0, "reasons": ["NO_PAGES"]}

    V.root_pub = inp["root"]["public_key"]
    V.audit_key_id = inp["audit"]["key_id"]
    V.audit_root_key = inp["root"]["key_id"]
    audit_pub = inp["audit"]["public_key"]

    cp = None
    for p in inp["pages"]:
        if cp is None:
            cp = p["checkpoint"]
        elif _canon(p["checkpoint"]) != _canon(cp):
            V.fail("HASH_MISMATCH")
            break
        c = p["checkpoint"]
        ok_hash = c["hash"] == D("WEATHER-CHECKPOINT/1", c["body"])
        if c["body"]["key_id"] != inp["audit"]["key_id"] or not ok_hash \
                or not V.sig(c, "WEATHER-CHECKPOINT-SIGN/1", audit_pub):
            V.fail("SIGNATURE_INVALID" if ok_hash else "HASH_MISMATCH")
            break
    if V.integrity_bad:
        return _finish(V, head0, inp.get("expected_head"))
    cpb = cp["body"]
    V.fleet = cpb["fleet"]

    for p in inp["pages"]:
        for o in p["objects"]:
            key = f"{o['kind']}:{o['hash']}"
            prior = V.objects.get(key)
            if prior is not None:
                if _canon(prior) != _canon(o["value"]):
                    V.fail("OBJECT_CONFLICT")
                continue
            body = o["value"].get("body") if isinstance(o["value"], dict) else None
            tag = {"config": "WEATHER-CONFIG/1", "manifest": "WEATHER-MANIFEST/1",
                   "result": "WEATHER-RESULT/1", "page": "WEATHER-PAGE/1"}[o["kind"]]
            want = D(tag, o["value"] if o["kind"] == "manifest" else body)
            declared = o["hash"] if o["kind"] == "manifest" else o["value"].get("hash")
            if o["hash"] != want or declared != o["hash"]:
                V.fail("HASH_MISMATCH")
                continue
            V.objects[key] = o["value"]

    entries = []
    for i, p in enumerate(inp["pages"]):
        prev_next = 0 if i == 0 else _u(inp["pages"][i - 1]["next_seq"])
        if _u(p["after_seq"]) != prev_next:
            V.fail("CHAIN_INVALID")
            break
        expect = _u(p["after_seq"]) + 1
        broke = False
        for e in p["entries"]:
            if _u(e["body"]["seq"]) != expect:
                V.fail("CHAIN_INVALID")
                broke = True
                break
            expect += 1
            entries.append(e)
        if broke:
            break
        last_seq = _u(p["entries"][-1]["body"]["seq"]) if p["entries"] else _u(p["after_seq"])
        if _u(p["next_seq"]) != last_seq:
            V.fail("CHAIN_INVALID")
            break

    prev = ZERO
    seq = 0
    last_at = -1
    for e in entries:
        if V.integrity_bad:
            break
        if e["hash"] != D("WEATHER-AUDIT/1", e["body"]):
            V.fail("HASH_MISMATCH")
            break
        if e["body"]["key_id"] != V.audit_key_id or not V.sig(e, "WEATHER-AUDIT-SIGN/1", audit_pub):
            V.fail("SIGNATURE_INVALID")
            break
        if e["body"]["fleet"] != V.fleet:
            V.fail("TRANSITION_INVALID")
            break
        if _u(e["body"]["seq"]) != seq + 1 or e["body"]["prev"] != prev:
            V.fail("CHAIN_INVALID")
            break
        at = _u(e["body"]["at_ms"])
        if at < last_at:
            V.fail("CHAIN_INVALID")
            break
        last_at = at
        seq += 1
        prev = e["hash"]
        V.positions[seq] = e["hash"]
        V.event(e["body"])
    if V.pw and V.pw["got"] != V.pw["expect"]:
        V.fail("TRANSITION_INVALID")
        V.pw = None
    verified_head = {"seq": str(seq), "hash": prev}

    if not V.integrity_bad and (verified_head["seq"] != cpb["head"]["seq"] or verified_head["hash"] != cpb["head"]["hash"]):
        V.fail("INCOMPLETE")

    _collect_refs(entries, V)
    for key in V.objects:
        if key not in V.referenced:
            V.fail("OBJECT_CONFLICT")

    return _finish(V, verified_head, inp.get("expected_head"))


def _collect_refs(entries, V):
    for e in entries:
        d = e["body"]["data"]
        k = e["body"]["kind"]
        if k in ("ConfigScheduled", "ConfigActivated", "KeysRevoked"):
            V.referenced.add(f"config:{d['config']}")
        elif k == "WindowFinalized":
            V.referenced.add(f"manifest:{d['manifest']}")
            m = V.objects.get(f"manifest:{d['manifest']}")
            if m:
                V.referenced.add(f"config:{m['config']}")
        elif k == "ResultFinalized":
            V.referenced.add(f"result:{d['result']}")
            r = V.objects.get(f"result:{d['result']}")
            if r:
                V.referenced.add(f"manifest:{r['body']['manifest']}")
                V.referenced.add(f"config:{r['body']['config']}")
        elif k == "DeliveryChanged":
            p = d.get("page")
            if p:
                V.referenced.add(f"page:{p}")
                pg = V.objects.get(f"page:{p}")
                if pg:
                    V.referenced.add(f"config:{pg['body']['config']}")
                    V.referenced.add(f"manifest:{pg['body']['manifest']}")
                    V.referenced.add(f"result:{pg['body']['result']}")


def _finish(V, head, expected):
    reasons = [r for r in _REASONS_ORDERED if r in V.reasons]
    if V.integrity_bad:
        return {"integrity": "INVALID", "replay": "INCOMPLETE", "completeness": "INCOMPLETE",
                "native_truth": "NOT_ATTESTED", "head": head, "reasons": reasons}
    replay = "MISMATCH" if V.replay_bad else ("INCOMPLETE" if V.incomplete else "MATCH")
    if expected is None:
        completeness = "UNPINNED_PREFIX"
    elif _u(expected["seq"]) <= _u(head["seq"]) and V.positions.get(_u(expected["seq"])) == expected["hash"]:
        completeness = "AT_PIN"
    else:
        completeness = "INCOMPLETE"
        reasons.append("HEAD_MISMATCH")
    return {"integrity": "VALID", "replay": replay, "completeness": completeness,
            "native_truth": "NOT_ATTESTED", "head": head, "reasons": reasons}
