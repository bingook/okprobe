#!/usr/bin/env python3
"""Git conflict resolver for okprobe state files (invoked by strike.yml commit-state).

Pull-conflict policy:
  *.csv   -> union by first column (last occurrence wins; header preserved)
  *.jsonl -> concatenated unique lines
  *.json  -> recursive dict union; lists unioned; numeric scalars -> max;
             other scalars -> theirs
  other   -> theirs (remote)
Always ends with `git add` on every touched file so the index is merge-ready.
"""
import json
import os
import subprocess


def git(*a):
    return subprocess.run(list(a), capture_output=True, text=True)


def stage_content(stage, path):
    """stage: ':2:' ours | ':3:' theirs. Returns text or None."""
    r = git("show", f"{stage}:{path}")
    if r.returncode != 0:
        return None
    return r.stdout


def union_csv(texts, path):
    lines = []
    for t in texts:
        if t:
            lines.extend(l.rstrip("\n") for l in t.splitlines() if l.strip())
    if not lines:
        return ""
    header = None
    if any(ch.isalpha() for ch in lines[0]):
        header = lines[0]
        lines = lines[1:]
    seen = {}
    for l in lines:
        key = l.split(",")[0]
        seen[key] = l  # last wins
    out = [header] if header else []
    out.extend(seen.values())
    return "\n".join(out) + "\n"


def merge_json(ours, theirs_text):
    a = ours if isinstance(ours, dict) else {}
    try:
        b = json.loads(theirs_text) if theirs_text else {}
    except Exception:
        b = {}
    if not isinstance(b, dict):
        return a

    def md(x, y):
        out = dict(x)
        for k, v in y.items():
            if k in out:
                ox = out[k]
                if isinstance(ox, dict) and isinstance(v, dict):
                    out[k] = md(ox, v)
                elif isinstance(ox, list) and isinstance(v, list):
                    out[k] = ox + [e for e in v if e not in ox]
                else:
                    try:
                        fx, fy = float(ox), float(v)
                        out[k] = fx if abs(fx - int(fx)) < 1e-9 and abs(fy - int(fy)) < 1e-9 else max(fx, fy)
                        if isinstance(out[k], float) and out[k].is_integer():
                            out[k] = int(out[k])
                    except Exception:
                        out[k] = v
            else:
                out[k] = v
        return out

    return md(a, b)


def main():
    r = git("diff", "--name-only", "--diff-filter=U")
    files = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    for path in files:
        ours = stage_content(":2:", path)
        theirs = stage_content(":3:", path)
        try:
            if path.endswith(".csv"):
                content = union_csv([ours, theirs], path)
            elif path.endswith(".jsonl"):
                seen, out = set(), []
                for t in (ours, theirs):
                    for l in (t or "").splitlines():
                        if l.strip() and l not in seen:
                            seen.add(l)
                            out.append(l)
                content = "\n".join(out) + ("\n" if out else "")
            elif path.endswith(".json"):
                oj = None
                try:
                    oj = json.loads(ours) if ours else None
                except Exception:
                    oj = None
                mj = merge_json(oj if oj is not None else {}, theirs)
                content = json.dumps(mj, ensure_ascii=False, indent=1)
            else:
                content = theirs if theirs is not None else (ours or "")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content if content.endswith("\n") or not content else content + "\n")
            git("add", path)
            print(f"resolved {path}", flush=True)
        except Exception as e:
            git("checkout", "--theirs", path)
            git("add", path)
            print(f"fallback-theirs {path} ({e})", flush=True)
    print("RESOLVE_CONFLICTS DONE", flush=True)


if __name__ == "__main__":
    main()
