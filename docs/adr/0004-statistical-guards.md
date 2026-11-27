# ADR 0004: Statistical guards for degradation and corroboration

**Status:** accepted · 2026-11-26

The spec's starting rule ("> 2% loss over ≥ 20 probes in 5 min") raised false incidents
in simulation: 4/150 timeouts happen by chance at 0.5% background loss, and across
40 nodes × 3 targets some window always crosses. Decisions:

- Degrade only when the observed loss exceeds the threshold **and** its one-sided 99%
  Wilson lower bound does too, with ≥ 3 timeouts. DNS bad-answer rates use the same
  proportional rule. Trade-off: over 150 probes, ~7% loss is needed to confirm; at
  lower loss the target shows its loss but is not marked degraded.
- Wireless-path and DNS client-path incidents require ≥ 2 vantages, ≥ 2 degraded
  targets at one vantage, or a hard failure (3 consecutive).
- AP hypotheses need a current symptom (a node still missing, failing management, or
  an absent radio); roams alone are supporting evidence.

Validated: all scenarios pass on 30 seeds. Thresholds remain configurable; tune per
site after a week of baseline.
