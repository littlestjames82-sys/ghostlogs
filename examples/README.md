# GhostLogs examples

`billing-api.log` is a small synthetic log from a fictional billing
service: 33 lines with a repeated poll line (x15), a repeated warning
(x6), and one gateway error with a Python traceback. The error line
carries a fake AWS-shaped key so the redaction is visible in the pack.
It is not a real credential and never was.

`incident-pack/` is what the tool produced from it:

```
PYTHONPATH=src python3 -m ghostlogs pack examples/billing-api.log -o examples/incident-pack --budget 2000
```

Result, as printed by the tool:

```
lines 33 = kept 15 + collapsed 18 + dropped 0 (reconciles: True)
windows: 1 emitted of 1 matched; duplicate groups: 2 emitted of 2
pack estimate 752 tokens against budget 2000
redactions: 1 {'aws-access-key': 1}
```

Open `incident-pack/INCIDENT.md` to see the pack an agent would read:
the timeline anchors, the error window with its context and traceback,
the repeated lines shown once each with exact counts, and a section
stating what was not shown and why. The fake key appears nowhere; in
its place the window shows `[REDACTED:aws-access-key]`.
`incident-pack/manifest.json` carries the same counts in machine
form, the source hash, the redaction counts by shape, and the limits
of the pack stated in writing.

To try a tighter budget:

```
PYTHONPATH=src python3 -m ghostlogs pack examples/billing-api.log -o /tmp/pack-tight --budget 300
```

The pack shrinks, the manifest records what was dropped and why, and
if even the mandatory anchors cannot fit, the pack is still written,
marked over budget, and the command exits nonzero rather than
pretending it fit.
