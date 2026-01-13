#!/usr/bin/env python3
import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple


DEFAULT_FUZZER_DIR = Path("/home/zwz/Libafl/fuzzers/full_system/qemu_baremetal")
DEFAULT_ZEPHYR_ROOT = Path("/home/zwz/zephyr")

OK_RETURN_CODES = {0, 101}  # 101 is commonly used by this runner to indicate breakpoint stop

CRASH_PATTERNS = [
    re.compile(r"\bASSERTION\b", re.IGNORECASE),
    re.compile(r"\bFATAL\b", re.IGNORECASE),
    re.compile(r"\bPANIC\b", re.IGNORECASE),
    re.compile(r"HardFault", re.IGNORECASE),
    re.compile(r"Segmentation fault", re.IGNORECASE),
    re.compile(r"\bexit=Crash\b", re.IGNORECASE),
    re.compile(r"\bcrash\b", re.IGNORECASE),
]


@dataclass(frozen=True)
class RunResult:
    elf: Path
    input_path: Path
    rc: Optional[int]
    timed_out: bool
    log_path: Path
    interesting: bool
    reason: str


def find_elfs(zephyr_root: Path) -> List[Path]:
    elfs: List[Path] = []
    for path in zephyr_root.rglob("zephyr.elf"):
        # Only accept the standard build layout */zephyr/zephyr.elf
        if path.parent.name == "zephyr":
            elfs.append(path)
    elfs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return elfs


def find_crash_inputs(crashes_dir: Path) -> List[Path]:
    if not crashes_dir.exists():
        return []
    inputs: List[Path] = []
    # Only treat alphanumeric filenames as actual crash inputs.
    # Exclude dotfiles and metadata sidecars.
    alnum_name = re.compile(r"^[A-Za-z0-9]+$")
    for p in sorted(crashes_dir.iterdir()):
        if not p.is_file():
            continue
        name = p.name
        # LibAFL may write metadata/hidden files next to actual inputs.
        if name.startswith("."):
            continue
        if name.endswith(".metadata"):
            continue
        # User rule: seed files are only letters+digits.
        if not alnum_name.match(name):
            continue
        inputs.append(p)
    return inputs


def _kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        return


def _kill_qemu_for_kernel(kernel_path: Path) -> None:
    """Best-effort cleanup for orphan QEMU processes started with -kernel <kernel_path>."""
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,args"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return

    needle = f"-kernel {kernel_path}"
    pids: List[int] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "qemu-system-arm" not in line:
            continue
        if needle not in line:
            continue
        try:
            pid_str = line.split(None, 1)[0]
            pids.append(int(pid_str))
        except Exception:
            continue

    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            pass


def _is_interesting_output(text: str) -> Tuple[bool, str]:
    for pat in CRASH_PATTERNS:
        if pat.search(text):
            return True, f"matched:{pat.pattern}"
    return False, ""


def run_replay(
    fuzzer_dir: Path,
    elf: Path,
    input_path: Path,
    timeout_s: int,
    out_dir: Path,
) -> RunResult:
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_elf = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(elf.relative_to(DEFAULT_ZEPHYR_ROOT)) if str(elf).startswith(str(DEFAULT_ZEPHYR_ROOT)) else elf.name)
    safe_input = re.sub(r"[^A-Za-z0-9_.-]+", "_", input_path.name)
    log_path = out_dir / f"replay__{safe_elf}__{safe_input}.log"

    env = os.environ.copy()
    env["REPLAY_INPUT"] = str(input_path)

    # NOTE: `just` variable overrides must come *before* the recipe name.
    # Using `just run kernel_ELF=...` would treat it as a positional arg and
    # can break the build invocation.
    cmd = ["just", f"kernel_ELF={elf}", "run"]

    start = time.time()
    timed_out = False
    rc: Optional[int] = None

    proc: Optional[subprocess.Popen] = None
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as logf:
            logf.write(f"[CMD] {' '.join(shlex.quote(c) for c in cmd)}\n")
            logf.write(f"[ENV] REPLAY_INPUT={env['REPLAY_INPUT']}\n")
            logf.write(f"[START] {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            logf.flush()

            proc = subprocess.Popen(
                cmd,
                cwd=str(fuzzer_dir),
                env=env,
                stdout=logf,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
                text=True,
            )
            try:
                rc = proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(proc)
                time.sleep(1)
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass

    finally:
        # best-effort orphan cleanup
        _kill_qemu_for_kernel(elf)

    dur = time.time() - start

    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        text = ""

    interesting, reason = _is_interesting_output(text)
    if timed_out:
        interesting = True
        reason = "timeout"

    if (rc is not None) and (rc not in OK_RETURN_CODES):
        interesting = True
        reason = reason or f"rc={rc}"

    if not interesting:
        reason = f"ok (rc={rc}, {dur:.2f}s)"

    return RunResult(
        elf=elf,
        input_path=input_path,
        rc=rc,
        timed_out=timed_out,
        log_path=log_path,
        interesting=interesting,
        reason=reason,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan Zephyr zephyr.elf candidates and replay known crash inputs to find a reproducible crash.")
    ap.add_argument("--fuzzer-dir", type=Path, default=DEFAULT_FUZZER_DIR)
    ap.add_argument("--zephyr-root", type=Path, default=DEFAULT_ZEPHYR_ROOT)
    ap.add_argument("--crashes-dir", type=Path, default=DEFAULT_FUZZER_DIR / "crashes")
    ap.add_argument("--out-dir", type=Path, default=Path("/tmp/elf_replay_scan"))
    ap.add_argument("--max-elfs", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--max-inputs", type=int, default=0, help="Limit number of crash inputs (0 = no limit)")
    ap.add_argument("--stop-on-hit", action="store_true", help="Stop immediately on the first interesting case")
    ap.add_argument(
        "--resume",
        action="store_true",
        help="Resume from an existing summary.txt (skip already processed (ELF,input) pairs)",
    )
    args = ap.parse_args()

    elfs = find_elfs(args.zephyr_root)[: args.max_elfs]
    inputs = find_crash_inputs(args.crashes_dir)
    if args.max_inputs and args.max_inputs > 0:
        inputs = inputs[: args.max_inputs]

    if not elfs:
        print(f"No zephyr.elf found under {args.zephyr_root}")
        return 2
    if not inputs:
        print(f"No crash inputs found under {args.crashes_dir}")
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.out_dir / "summary.txt"

    processed: Set[Tuple[str, str]] = set()
    if args.resume and summary_path.exists():
        try:
            cur_elf: Optional[str] = None
            for line in summary_path.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^=== ELF \d+/\d+: (.+) ===$", line)
                if m:
                    cur_elf = m.group(1).strip()
                    continue
                m2 = re.match(r"^\s*input=([^\s]+)\s+", line)
                if m2 and cur_elf:
                    processed.add((cur_elf, m2.group(1)))
        except Exception:
            processed = set()

    summary_mode = "a" if (args.resume and summary_path.exists()) else "w"
    hits: List[RunResult] = []

    with open(summary_path, summary_mode, encoding="utf-8") as sf:
        if summary_mode == "w":
            sf.write(f"fuzzer_dir={args.fuzzer_dir}\n")
            sf.write(f"zephyr_root={args.zephyr_root}\n")
            sf.write(f"crashes_dir={args.crashes_dir}\n")
            sf.write(f"max_elfs={args.max_elfs}\n")
            sf.write(f"timeout={args.timeout}\n")
            sf.write("\n")
        else:
            sf.write("\n")
            sf.write(f"[RESUME] {time.strftime('%Y-%m-%d %H:%M:%S')} processed_pairs={len(processed)}\n")
            sf.write("\n")

        for i, elf in enumerate(elfs, start=1):
            sf.write(f"=== ELF {i}/{len(elfs)}: {elf} ===\n")
            sf.flush()
            print(f"[SCAN] ELF {i}/{len(elfs)}: {elf}")

            for idx, inp in enumerate(inputs, start=1):
                if args.resume and (str(elf), inp.name) in processed:
                    if idx % 200 == 0:
                        print(f"[SCAN]   ... {idx}/{len(inputs)} inputs skipped")
                    continue
                res = run_replay(args.fuzzer_dir, elf, inp, args.timeout, args.out_dir)
                sf.write(f"  input={inp.name} interesting={res.interesting} {res.reason} log={res.log_path}\n")
                sf.flush()

                if res.interesting:
                    hits.append(res)
                    print(f"[HIT] {res.reason}\n      elf={elf}\n      input={inp}\n      log={res.log_path}")
                    if args.stop_on_hit:
                        return 0
                else:
                    # keep stdout concise: periodic progress only
                    if idx % 25 == 0:
                        print(f"[SCAN]   ... {idx}/{len(inputs)} inputs ok")

    if hits:
        print(f"Finished scan with hits={len(hits)}")
        print(f"See summary: {summary_path}")
        return 0

    print("No interesting case found in the scanned range.")
    print(f"See summary: {summary_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
