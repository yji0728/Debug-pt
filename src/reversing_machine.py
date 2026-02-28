#!/usr/bin/env python3
"""Reversing Optimization Machine

A lightweight CLI that turns branch/call/return trace events into prioritized
reverse-engineering targets.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


TRACKED_TYPES = {"branch", "call", "ret", "indirect_jump", "mem_write"}


@dataclass
class FunctionStats:
    name: str
    events: int = 0
    branches: int = 0
    calls: int = 0
    returns: int = 0
    indirect: int = 0
    mem_writes: int = 0
    unique_targets: set[str] = field(default_factory=set)
    target_hist: Counter = field(default_factory=Counter)

    def observe(self, event: dict) -> None:
        et = event.get("type")
        self.events += 1

        if et == "branch":
            self.branches += 1
        elif et == "call":
            self.calls += 1
        elif et == "ret":
            self.returns += 1
        elif et == "indirect_jump":
            self.indirect += 1
        elif et == "mem_write":
            self.mem_writes += 1

        target = event.get("target")
        if target:
            self.unique_targets.add(str(target))
            self.target_hist[str(target)] += 1

    @property
    def indirect_ratio(self) -> float:
        return self.indirect / max(self.events, 1)

    @property
    def call_balance(self) -> float:
        # close to 0 means call/return pair is balanced
        total = self.calls + self.returns
        if total < 10:
            return 0.0
        return abs(self.calls - self.returns) / total

    @property
    def target_entropy(self) -> float:
        total = sum(self.target_hist.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for c in self.target_hist.values():
            p = c / total
            entropy -= p * math.log2(p)
        return entropy

    def score(self) -> float:
        score = 0.0
        score += min(self.indirect_ratio * 4.0, 2.5)
        score += min(self.target_entropy / 2.0, 2.5)
        score += min(self.mem_writes / max(self.events, 1), 1.0)

        # high branch density tends to mean control-flow machinery
        branch_density = self.branches / max(self.events, 1)
        score += min(branch_density * 2.0, 2.0)

        # imbalance can indicate flattening dispatcher weirdness
        score += min(self.call_balance * 2.0, 2.0)
        return round(score, 3)

    def classify(self) -> list[str]:
        tags: list[str] = []
        if self.indirect_ratio >= 0.2 and len(self.unique_targets) >= 3:
            tags.append("possible_switch_dispatch")
        if self.branches >= 80 and self.call_balance >= 0.4:
            tags.append("possible_flattening")
        if self.target_entropy >= 2.4 and self.indirect_ratio >= 0.1:
            tags.append("high_variance_control_flow")
        if self.mem_writes > self.events * 0.35:
            tags.append("self_modifying_or_state_heavy")
        if not tags:
            tags.append("likely_normal_logic")
        return tags


def load_events(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            et = obj.get("type")
            if et not in TRACKED_TYPES:
                continue
            obj.setdefault("func", f"unknown@{obj.get('ip', '0x?')}")
            obj["_line"] = line_no
            yield obj


def analyze(events: Iterable[dict]) -> list[FunctionStats]:
    stats: dict[str, FunctionStats] = {}
    edge_counter = defaultdict(int)

    for ev in events:
        fn = str(ev["func"])
        if fn not in stats:
            stats[fn] = FunctionStats(name=fn)
        stats[fn].observe(ev)

        src = str(ev.get("ip", "?"))
        dst = str(ev.get("target", "?"))
        edge_counter[(src, dst)] += 1

    ranked = sorted(stats.values(), key=lambda s: s.score(), reverse=True)
    return ranked


def as_report(ranked: list[FunctionStats], top_k: int) -> dict:
    top = ranked[:top_k]
    return {
        "machine": "reverse-optimization-v1",
        "strategy": [
            "trace-first",
            "rule-engine-before-llm",
            "replay-and-diverge",
        ],
        "hotspots": [
            {
                "function": s.name,
                "score": s.score(),
                "events": s.events,
                "indirect_ratio": round(s.indirect_ratio, 3),
                "target_entropy": round(s.target_entropy, 3),
                "call_balance": round(s.call_balance, 3),
                "tags": s.classify(),
                "next_actions": [
                    "snapshot_or_replay_before_entry",
                    "mutate_input_or_register_1_to_2_bytes",
                    "re-run_trace_and_compare_edges",
                ],
            }
            for s in top
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Build optimized reversing hotspots from trace JSONL")
    p.add_argument("trace", type=Path, help="Path to JSONL trace file")
    p.add_argument("-k", "--top-k", type=int, default=10, help="How many hotspots to return")
    p.add_argument("-o", "--output", type=Path, default=None, help="Optional output JSON path")
    args = p.parse_args()

    ranked = analyze(load_events(args.trace))
    report = as_report(ranked, args.top_k)
    text = json.dumps(report, ensure_ascii=False, indent=2)

    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
