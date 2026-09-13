"""python -m lattice_weather — offline tools (§6.3): replay, verify, eval."""

import argparse
import json
import sys


def _load(path):
    from .strictjson import parse_bytes
    with open(path, "rb") as f:
        return parse_bytes(f.read())


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lattice_weather", description="Weather offline tools (protocol weather/1)")
    ap.add_argument("--json", action="store_true", help="emit JSON output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("replay", help="core.replay over a committed window")
    rp.add_argument("input", help="ReplayInput JSON file")

    vf = sub.add_parser("verify", help="evidence.verify over exported bundle pages")
    vf.add_argument("input", help="VerifyInput JSON file")

    ev = sub.add_parser("eval", help="eval.run against the pinned vector corpus")
    ev.add_argument("--vectors", required=True, help="conformance vectors JSON")
    ev.add_argument("--suite", default=None, help="EvalSuite JSON (optional)")
    ev.add_argument("--pack-digest", required=True)
    ev.add_argument("--corpus-digest", required=True)
    ev.add_argument("--seed", default="0")

    args = ap.parse_args(argv)

    if args.cmd == "replay":
        from .replay import replay
        out = replay(_load(args.input))
    elif args.cmd == "verify":
        from .verify import verify
        out = verify(_load(args.input))
    elif args.cmd == "eval":
        from .evaluate import eval_run
        vectors = _load(args.vectors)
        suite = _load(args.suite) if args.suite else None
        cfg = {
            "v": 1, "suite": "weather-conformance/1", "pack_digest": args.pack_digest,
            "seed": args.seed, "allow_seed_override": False,
            "corpus_digest": args.corpus_digest, "implementations": ["python"],
        }
        out = eval_run(cfg, vectors, suite, "python")
    else:  # pragma: no cover
        ap.error("unknown command")

    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
