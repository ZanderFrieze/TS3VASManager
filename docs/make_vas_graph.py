#!/usr/bin/env python3
"""
Build the VAS comparison graph for the README.

Parses the three saved VAS_COMBINED captures and plots 9 lines:
  3 runs x 3 metrics (total_free, largest_free, script_heap).
Each RUN gets a base colour (red / green / blue); each METRIC within a run
is a different shade of that run's colour.

x-axis  = elapsed time from each run's start, formatted H:MM (:30, 1:00, 1:30...).
          Runs are kept at their full, individual length on purpose.
y-axis  = MB.  Both axes start at the (0,0) origin.

Reads from:   C:\\ts3_tool\\Keep for Graph\\*.txt
Writes:       docs/vas_comparison.png  and  docs/vas_comparison.csv
"""
import re, csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, FuncFormatter

SRC_DIR = r"C:\ts3_tool\Keep for Graph"
OUT_PNG = os.path.join(os.path.dirname(__file__), "vas_comparison.png")
OUT_CSV = os.path.join(os.path.dirname(__file__), "vas_comparison.csv")

# (filename, short run descriptor, {metric: shade})
# shade order: largest_free darkest (primary), total_free mid, script_heap lightest
RUNS = [
    ("Long run stress.txt", "Main PC · v1.67 · full catalog",
        {"largest_free": "#B00000", "total_free": "#E45757", "script_heap": "#F6B0B0"}),
    ("MainPCRiverview.txt", "Main PC · v1.67 · Riverview",
        {"largest_free": "#0A7A0A", "total_free": "#3FB23F", "script_heap": "#A6DFA6"}),
    ("ALLY X run.txt", "ROG Ally X · v1.69 · Riverview",
        {"largest_free": "#103FB0", "total_free": "#4F7FE6", "script_heap": "#AFC4F5"}),
]

LINE = re.compile(
    r"^\[(\d{2}):(\d{2}):(\d{2})\.(\d{3})\].*?VAS_REPORT\] Local VAS: "
    r"total_free=(\d+) MB largest_free=(\d+) MB.*?script_heap=(\d+) MB")

def hm(mins):
    """elapsed minutes -> H:MM time label (:30, 1:00, 1:30, 6:02 ...)."""
    mins = int(round(mins))
    h, m = divmod(mins, 60)
    if h == 0:
        return "0:00" if m == 0 else f":{m:02d}"
    return f"{h}:{m:02d}"

def parse(path):
    rows = []  # (elapsed_min, total_free, largest_free, script_heap)
    t0 = None
    for ln in open(path, "r", errors="ignore"):
        m = LINE.match(ln)
        if not m:
            continue
        h, mi, s, ms, tf, lf, sh = m.groups()
        t = int(h)*3600 + int(mi)*60 + int(s) + int(ms)/1000.0
        if t0 is None:
            t0 = t
        e = t - t0
        if e < 0:                       # guard against midnight wrap
            e += 24*3600
        rows.append((e/60.0, int(tf), int(lf), int(sh)))
    # drop trailing shutdown snapshot(s): once Mono unloads, script_heap reads 0
    # again and free VAS spikes -- not gameplay, so trim from the last sh>0 sample.
    last = len(rows) - 1
    while last > 0 and rows[last][3] == 0:
        last -= 1
    return rows[:last+1]

plt.figure(figsize=(14, 8))
all_csv = []
max_x = 0.0
max_y = 0.0
for fname, desc, shades in RUNS:
    rows = parse(os.path.join(SRC_DIR, fname))
    if not rows:
        print("WARN: no rows parsed from", fname); continue
    xs = [r[0] for r in rows]
    tf = [r[1] for r in rows]
    lf = [r[2] for r in rows]
    sh = [r[3] for r in rows]
    ended = hm(xs[-1])
    plt.plot(xs, lf, color=shades["largest_free"], linewidth=1.8,
             label=f"{desc} — ended ~{ended} — largest_free")
    plt.plot(xs, tf, color=shades["total_free"], linewidth=1.4,
             label="      — total_free")
    plt.plot(xs, sh, color=shades["script_heap"], linewidth=1.4,
             label="      — script_heap")
    max_x = max(max_x, xs[-1])
    max_y = max(max_y, max(tf))
    print(f"{fname:24s} span={xs[-1]/60:.2f}h ({ended})  start_lf={lf[0]} end_lf={lf[-1]}  samples={len(rows)}")
    for r in rows:
        all_csv.append((fname, *r))

ax = plt.gca()
ax.set_xlim(0, max_x)                 # x starts at the 0 origin
ax.set_ylim(0, max_y * 1.02)          # y starts at the 0 origin
ax.xaxis.set_major_locator(MultipleLocator(30))   # a tick every 30 min
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: hm(v)))

ax.axvspan(0, 180, color="0.92", zorder=0)        # 2-3h "recommended" window
ax.text(90, max_y * 0.03, "current 2-3h\nrecommended window",
        ha="center", va="bottom", fontsize=8, color="0.4")

plt.title("The Sims 3 (32-bit) VAS over a session — 3 runs x 3 metrics\n"
          "remaining address space left to the GAME after the proxy's 1 GB arena "
          "(MEM_FREE only); runs kept at full length", fontsize=11)
plt.xlabel("elapsed time from run start (H:MM)")
plt.ylabel("MB")
plt.grid(True, alpha=0.3)
plt.legend(fontsize=7, loc="upper right", framealpha=0.9)
plt.tight_layout()
plt.savefig(OUT_PNG, dpi=150)
print("wrote", OUT_PNG)

with open(OUT_CSV, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["source", "elapsed_min", "total_free_mb", "largest_free_mb", "script_heap_mb"])
    w.writerows(all_csv)
print("wrote", OUT_CSV)
