# GhostLogs

A log slicer for GhostSlice. GhostSlice governs what an agent reads
from a codebase; GhostLogs governs what an agent reads from a log
file. It turns one large local log into a small incident pack: the
error windows, the repeated lines shown once with exact counts, and a
written record of everything that was left out and why.

The pack is evidence, not a diagnosis. GhostLogs shows what matched,
how often, and in what order. It never claims why the failure
happened.

## What it does

Given one log file and a token budget, GhostLogs writes a pack folder
with two files:

- `INCIDENT.md`, the readable pack: timeline anchors (the first and
  last lines and timestamps), error windows with their surrounding
  context and stack traces, duplicate exemplars with exact occurrence
  counts, and a plain statement of what was not shown.
- `manifest.json`, the same facts in machine form: source path, size
  and sha256, the token budget and the pack estimate, and line counts
  that must reconcile exactly: total lines in = kept + collapsed +
  dropped, with dropped split by reason.

Three things happen on the way in:

- Error windows. Lines matching the built-in patterns (FATAL,
  CRITICAL, ERROR, panic markers, traceback starts, exception names)
  open a window of context lines. Overlapping windows merge, and
  stack traces are absorbed into their window.
- Duplicate collapse. Repeated lines collapse to one exemplar with an
  exact count and first and last line numbers. Near duplicates are
  grouped after masking timestamps, numbers, hex ids, UUIDs, IPs, and
  quoted strings; each exemplar also reports how many of its copies
  were byte-identical, so over-grouping is visible rather than
  hidden.
- Redaction, on by default. Secret-shaped literals in emitted
  excerpts are replaced with a typed placeholder such as
  `[REDACTED:aws-access-key]`. The value is never printed in the
  pack, the manifest, or the terminal output. Counts per shape are
  recorded in the manifest. `--no-redact` exists for local debugging
  and is recorded in the manifest when used.

## Quick start

```
ghostlogs pack app.log -o incident-pack --budget 4000
ghostlogs doctor
```

`pack` prints a short summary: the reconciled line counts, how many
windows and duplicate groups were emitted, the pack estimate against
the budget, which budget tier shipped, and the redaction counts. If
the mandatory content alone exceeds the budget, the pack is still
written, marked over budget in the manifest and in a Pack status
section in `INCIDENT.md` itself, and the command exits nonzero. It
never pretends a pack fit when it did not.

`doctor` reports the version, the token estimator in use, and the
pattern set loaded.

With no install, from the repo root:

```
PYTHONPATH=src python3 -m ghostlogs pack app.log -o incident-pack
```

## How the budget works

Emission priority is: timeline anchors first (always kept), then
error windows (highest severity, then file order), then duplicate
exemplars (highest count first). Anything that does not fit is
counted as dropped with its reason in the manifest. Windows are never
truncated in the middle.

Fit is decided by a tier ladder. The builder renders each tier,
measures the real pack, and ships the first tier that fits:

- `full`: every selected window and exemplar shown in full.
- `trimmed`: windows shown with plain context lines trimmed away;
  matched lines, trace lines, and repeat representatives kept.
- `exemplars`: error windows omitted; anchors and duplicate
  exemplars shown.
- `anchors`: only the mandatory timeline anchors shown.

The shipped tier is recorded in the manifest as `budget_tier`, with
a plain-words `budget_tier_meaning` beside it, and stated on the
face of `INCIDENT.md` whenever the tier is below `full`. The
over-budget path (pack written, marked, nonzero exit) is reached
only when even the anchors tier cannot fit. Token figures are
estimates from the GhostSlice calibrated estimator when GhostSlice
is reachable, or a documented fallback when it is not; the manifest
stamps which method was used. Estimates are not a vendor tokenizer
count.

One quirk worth knowing: the pack header names the source by its
absolute path, and the estimate counts the pack exactly as written,
so the same log at a longer path estimates slightly higher. Measured
on the example log: a source path 62 characters longer added 28
estimated tokens. The manifest's sha256 is the pack's identity
either way; the path is provenance, not identity.

## Safety and scope

- The source log is never modified, moved, or copied wholesale. Only
  selected, redacted excerpts are emitted. The tests hash the source
  before and after a run to hold this.
- Local files only. No network, no upload, no log server, no account.
- One file per pack. No live tailing or daemon mode in v0.1.
- Pure Python standard library, zero dependencies.

## Honest limits

- Pattern-based finding only sees what the patterns name. A failure
  written in words no pattern matches produces a pack with no error
  windows, and the pack says exactly that: no lines matched the
  pattern set. It never says nothing went wrong.
- Near-duplicate masking can over-collapse: two genuinely different
  errors that differ only in a masked part (a number, an id) share
  one exemplar. The exemplar is the first occurrence verbatim and the
  byte-identical count is shown beside the total, but the grouping
  can still hide a distinction that mattered.
- Repeated lines inside an error window are counted separately from
  the routine duplicate groups: the manifest carries them as window
  duplicate groups with exact occurrence counts, and the pack lists
  them under "Repeated lines inside error windows". Inside the
  window itself, consecutive repeats collapse in place under a note,
  so the window shows one copy while the exact total is stated in
  the counts.
- Stack trace absorption covers Python tracebacks, Java-style frames
  and Caused by chains, and generic indented continuations. Exotic
  formats may split a trace across windows.
- Secret-shape matching is exact about lengths, by design. The AWS
  access key shape is `AKIA` or `ASIA` plus exactly 16 characters
  (20 in total, the same shape GhostSlice's guard uses), so a
  longer or shorter look-alike is not that shape and is not
  redacted under that name. The other provider shapes (GitHub,
  `sk-`, Slack, JWT, bearer) are minimum-length. A generic
  assignment (`password=...` and kin) is redacted only when the
  name looks sensitive and the value is at least 8 characters with
  at least 4 distinct characters, and is not an obvious placeholder.
  Redaction lowers risk; it is not a guarantee that every credential
  form is caught.
- The log is read in a single streaming pass, so very large files are
  fine, but the duplicate signature table grows with the number of
  distinct normalised lines.

## Layout

- `src/ghostlogs/`: the core (patterns, analysis, redaction, pack
  writer, CLI).
- `tests/`: black-box tests against the CLI, including planted-repeat
  and planted-secret fixtures with exact ground truth.
- `examples/`: a synthetic noisy log and the incident pack built
  from it.

MIT licensed, same as the rest of the GhostSlice family.
