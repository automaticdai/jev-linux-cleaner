# jev-cleaner: a Linux disk cleaner that judges unknown leftovers

Date: 2026-09-20
Status: approved design, not yet implemented

## 1. Problem

Rule-based cleaners only know the paths someone put in a list. On Linux the
interesting junk is exactly the junk no list covers: a cache directory belonging
to a tool released last month, a `~/.config` directory left behind by software
uninstalled two years ago, a 5.8 GB `~/.cache/uv` tree that is safe to delete
but expensive to rebuild.

The XDG conventions make this worse rather than better, because applications
ignore them. `~/.cache/<app>` sometimes holds durable state; `~/.local/share/<app>`
sometimes holds pure cache. Location alone does not settle what a directory is.

A concrete example from the development machine, all four inside `~/.cache`:

| Directory | Size | What deletion actually costs |
| --- | --- | --- |
| `uv` | 5.8 GB | a slower next resolve, automatic |
| `ms-playwright` | 2.0 GB | broken until `playwright install` is run by hand |
| `huggingface` | 469 MB | a long model re-download, automatic |
| `mesa_shader_cache` | 2.5 MB | nothing noticeable |

`rm -rf ~/.cache` treats all four identically. Telling them apart is a semantic
judgment about unfamiliar software, which is what Jev supplies.

## 2. Scope

**In scope for v1**

- Scan of the user's home (`~/.cache`, `~/.local/share`, `~/.local/state`,
  orphaned `~/.config` directories, `~/.local/share/Trash`, browser profiles,
  toolchain caches) and of system locations read through `sudo`
  (`/var/cache/apt/archives`, `/var/log`, journald, `/tmp`, `/var/tmp`, old
  kernels, `dpkg` residual-config packages, disabled snap revisions), plus the
  container layer (dangling images, stopped containers, build cache) when the
  Docker socket is reachable.
- A Jev judgment for every candidate group that survives the safety floor.
- A tiered report, a re-tierable run artifact, and a generated but unexecuted
  `plan.sh`.

**Explicitly out of scope for v1**

- Deleting anything. v1 never removes a file. See section 8.
- Natural-language cleanup intent ("free space but keep me logged in"). It is a
  layer over the per-group judgments and needs them to exist first.
- Non-Debian package managers. The inventory module has a pluggable backend, but
  only dpkg, snap and docker ship in v1.
- A GUI.

**Target platform:** Ubuntu 24.04 (developed and tested on WSL2), Python 3.12.

## 3. Architecture

```
roots.yaml ─▶ scan.py ──▶ evidence.py ─▶ [denylist] ─▶ judge.py ─▶ policy.py ─▶ report.py
                 │         (pure)         (pure)        (network)   (pure)      (pure)
                 ├─ user scope: in-process, runs as the user
                 └─ system scope: sudo python -m jev_cleaner.probe --json
                                  (read-only, stdlib only, no network, no delete)
      inventory.py ────────────────┘                  rules.py ──────────────▶ baseline column
```

One direction of flow. Exactly one module touches the network (`judge.py`) and
exactly one runs privileged (`probe.py`).

### 3.1 Privilege separation

The main process never runs as root. System-scope scanning shells out to
`sudo python -m jev_cleaner.probe --roots system --json`, a module that imports
only the standard library, walks directories read-only, writes JSON to stdout
and exits. It holds no API key in its environment and contains no deletion code
at all. The privileged surface is therefore a single auditable file.

### 3.2 Modules

| Module | Purity | Responsibility |
| --- | --- | --- |
| `roots.py` + `roots.yaml` | data | the scan surface, per scope; edited to widen the scan |
| `scan.py` | Linux I/O | `os.scandir` walk to bounded depth, emits `ScanRecord` list as JSON |
| `probe.py` | Linux I/O, privileged | the same walk for system roots, stdlib only, read-only |
| `inventory.py` | Linux I/O | installed software from dpkg, snap, docker, `$PATH` |
| `evidence.py` | pure | rolls records into candidate groups and builds each group's Jev state |
| `denylist.py` | pure | the hard safety floor; drops groups before any request |
| `rules.py` | pure | known-path baseline verdicts, for comparison only |
| `judge.py` | network | Jev client, question battery, concurrency, answer cache |
| `policy.py` | pure | raw answers to tier, thresholds from config |
| `report.py` | pure | terminal table, `run.json`, `plan.sh` |
| `cli.py` | glue | `scan`, `report`, `explain`, `plan`, `disagree` |

Everything downstream of `scan.py` consumes JSON, so the whole pipeline runs
against a captured scan with no filesystem and no network.

### 3.3 Candidate groups

The unit of judgment is a directory, never a file: a home directory holds
millions of files and Jev accepts 64k tokens per request (32k for state plus the
longest question).

Grouping rule: each immediate child of a scan root is one group. A group is
split one level deeper only when it is both large (over 500 MB by default) and
heterogeneous (no single subdirectory holds more than 60% of its bytes). Total
groups are capped per run, default 400.

At roughly 2k tokens per group, a 400-group scan costs about one million input
tokens, which is about 4 cents at Jev's $0.042 per Mtok.

## 4. The state sent to Jev

Every value that is numeric or temporal is converted to words by `evidence.py`
before it is sent. `jev-1.13` is documented as unreliable at counting, numeric
comparison and date ordering, so no arithmetic and no date comparison is ever
asked of it.

```json
{
  "directory": {
    "path": "~/.cache/ms-playwright",
    "location_convention": "inside ~/.cache, which by XDG convention holds regenerable data",
    "size": "2.0 GB",
    "size_bucket": "very large, over 1 GB",
    "file_count": "about 12,000 files",
    "last_modified": "within the last week",
    "oldest_content": "about 8 months old",
    "top_extensions": [".so (3,100)", ".pak (210)", "no extension (900)"],
    "subdirectories": ["chromium-1140", "firefox-1450", "webkit-2070"],
    "sample_names": ["chromium-1140/chrome-linux/chrome", ".links", "ffmpeg-1011"]
  },
  "system": {
    "distribution": "Ubuntu 24.04",
    "possibly_related_installed_software": ["python3-playwright"]
  }
}
```

`possibly_related_installed_software` is a filtered slice, computed in code by
fuzzy-matching the directory name against the inventory. The full package list is
never sent: accuracy falls as state fills with detail unrelated to the decision.

## 5. The question battery

All seven questions go in one request per group. Questions in a request are
evaluated in parallel against the same state and cost only their own tokens, so
asking a question whose answer may go unused is close to free.

| id | type | judgment |
| --- | --- | --- |
| `content_kind` | Choice | what is stored here |
| `loss_if_deleted` | Score | what the user loses |
| `breaks_if_deleted` | Noul | deleting it breaks the installed software |
| `recreated_automatically` | Noul | the software rebuilds it unaided |
| `orphaned` | Noul | the owning software is gone |
| `holds_credentials` | Noul | deleting it signs the user out |
| `privacy_traces` | Noul | it records what the user did |

### 5.1 `content_kind` (Choice)

Instructions: "What is stored in the directory `directory.path`?"

| option | criteria |
| --- | --- |
| `regenerable_cache` | Data the program rebuilds or re-downloads by itself the next time it runs. |
| `downloaded_artifacts` | Packages, binaries, browsers or model files fetched over the network, restored only by downloading them again. |
| `build_output` | Compiled objects or build artifacts produced from source code that still exists elsewhere. |
| `transient_runtime_state` | Logs, crash dumps, sockets, pid files and temporary working files. |
| `application_settings` | Configuration and preferences the user set up. |
| `user_content` | Documents, saves, notes, keys or other material the user created or cannot obtain again. |
| `installed_program_files` | The program itself rather than its data. |
| `unclear` | The evidence does not identify what is stored here. |

The `unclear` option exists so that "not enough evidence" is reported rather
than guessed.

### 5.2 `loss_if_deleted` (Score)

Instructions: "What does the user lose if the directory `directory.path` is
deleted while the software that uses it stays installed?"

1. Nothing noticeable. The program rebuilds it silently and the user never sees a difference.
2. A slower next run. The program re-downloads or regenerates the data on its own, costing time or bandwidth but requiring no action from the user.
3. The user must run a command to restore it, such as re-installing a component or re-downloading a model.
4. Session or personalization is lost: the user is signed out, or history, preferences and customizations disappear.
5. Data the user created, or cannot obtain again, is destroyed.

Each level describes a concrete situation and stands on its own. This is the
judgment that separates `mesa_shader_cache` (1) from `uv` (2) from
`ms-playwright` (3).

### 5.3 The Nouls

Each is worded as a direct statement, in the affirmative, about a named part of
the state. No negations and no chained references, which cost accuracy.

- `breaks_if_deleted`: "Deleting the directory `directory.path` while the software remains installed would leave that software broken or unable to start until it is reinstalled or repaired."
- `recreated_automatically`: "The next time the software runs, it recreates the contents of `directory.path` by itself, without the user running any command."
- `orphaned`: "The directory `directory.path` belongs to software that is no longer installed on this system." Criteria name `system.possibly_related_installed_software` as the evidence for yes and no.
- `holds_credentials`: "The directory `directory.path` holds login sessions, cookies, tokens or keys, so deleting it would sign the user out or require re-authentication."
- `privacy_traces`: "The directory `directory.path` holds a record of what the user did: browsing history, search terms, opened files or command history."

### 5.4 What is never asked

Jev is never asked whether a directory should be deleted. That is a policy
question. Keeping it in code means a changed threshold re-tiers an entire stored
run with no new requests, and it keeps the raw judgments reusable.

Recency is also never asked. Whether a directory was touched today is computed
from mtimes in code.

### 5.5 Escalation pass

When `content_kind` returns `unclear`, or its confidence is below 0.5, and the
group is over 500 MB, code builds a second, richer state: one directory
level deeper, more sample names, and the text of any `package.json`,
`metadata.json` or `README` found inside. It then re-asks the battery.

This is the legitimate case for a second request, because the second state
cannot be constructed until the first answer exists. Escalation is capped at 25 groups per run by default.

## 6. The safety floor

Enforced in `denylist.py`, before any request is built. Denied groups are dropped
from the pipeline: they are never sent to Jev, never tiered, and never appear in
a plan. A wrong model answer about `/etc` is not outvoted, it cannot occur.

- System roots: `/`, `/etc`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/dev`, `/proc`, `/sys`, `/run`, except the cache paths explicitly listed in `roots.yaml`.
- Secrets: `~/.ssh`, `~/.gnupg`, `~/.password-store`, `~/.local/share/keyrings`.
- User content: `~/Documents`, `~/Desktop`, `~/Pictures`, `~/Videos`, `~/Music`, and any path the user lists under `protect:`.
- Any path with a `.git` directory at or above it.
- Any group modified within the last 15 minutes.
- Symbolic links are never followed and mount boundaries are never crossed.

## 7. Policy and tiering

`policy.py` is a pure function from the answer set to a tier. Thresholds live in
`policy.yaml` and the resolved values are stamped into every run artifact.

| Tier | Condition |
| --- | --- |
| `clean` | `content_kind` in {`regenerable_cache`, `build_output`, `transient_runtime_state`} with confidence >= 0.7, and `loss_if_deleted` <= 2.0, and `breaks_if_deleted` <= 0.15, and `holds_credentials` <= 0.10 |
| `costly` | `content_kind` is `downloaded_artifacts`, or `loss_if_deleted` is above 2.0 and below 4.0 |
| `orphan` | `orphaned` >= 0.8 and `content_kind` is not `user_content` |
| `review` | `content_kind` is `unclear`, or any Choice or Score confidence < 0.5 |
| `keep` | `content_kind` in {`user_content`, `application_settings`, `installed_program_files`}, or `loss_if_deleted` >= 4.0, or `breaks_if_deleted` > 0.5 |

Rules are applied in the order `keep`, `review`, `orphan`, `costly`, `clean`:
the most conservative tier that matches wins.

Confidence is used as the docs describe, as a second axis: an answer the model
itself reports as uncertain (< 0.5) never reaches `clean`, whatever it says.
Noul answers carry no confidence and are thresholded on the probability alone.
Thresholds tuned against one model version are not carried to another; the run
artifact records the versioned model ID that answered.

The `costly` tier exists because `uv`, `huggingface` and `ms-playwright` are all
genuinely reclaimable and genuinely expensive to restore. Folding them into
`clean` would eventually delete 8 GB the user wanted; folding them into `keep`
would hide the largest reclaim on the machine.

## 8. Output

**Terminal table.** Grouped by tier, largest first. Columns: path, size,
`content_kind`, `loss_if_deleted`, tier, the deciding judgment as a short "why",
and a baseline column marking agreement or disagreement with `rules.py`.
Footer: reclaimable bytes per tier, tokens and cost for the run, model ID.

**`runs/<timestamp>/run.json`.** Evidence, every raw probability and confidence,
the resolved policy values, the model ID and timings. Because the raw judgments
are stored, `jev-cleaner report --run latest` re-tiers a completed run under
changed thresholds with no API calls.

**`plan.sh`.** Generated, commented, and never executed by the tool. Clean-tier
entries appear as live `rm -rf` lines; every other tier appears commented out
with its reason. The user reads it and runs it themselves. This is what
report-only means here: the tool does the work and leaves the decision.

**CLI.**

| Command | Purpose |
| --- | --- |
| `jev-cleaner scan [--user] [--system] [--containers]` | walk, judge, write a run |
| `jev-cleaner report [--run latest] [--tier clean]` | re-tier and render a stored run, no network |
| `jev-cleaner explain <path>` | one group: state sent, every probability and confidence |
| `jev-cleaner plan [--run latest]` | write `plan.sh` |
| `jev-cleaner disagree [--run latest]` | every row where Jev and the rule baseline differ |

`explain` is the debugging verb. `disagree` is the evaluation verb.

## 9. Testing

Test-driven, and structured so that the network and the filesystem are both
optional.

- **Fixtures.** A captured scan of the development machine
  (`tests/fixtures/scan-ubuntu-2404.json`) plus synthetic groups for edge cases:
  empty directories, a directory of symlinks, a `.git` tree, a path under
  `protect:`, a group modified seconds ago.
- **Pure modules.** `evidence`, `denylist`, `rules` and `policy` are covered by
  table-driven unit tests. Policy tiering in particular gets one case per
  boundary condition in section 7.
- **`judge.py`.** Tested against recorded response cassettes in
  `tests/fixtures/answers/`. CI never contacts the API. A separate, opt-in
  `--live` run refreshes the cassettes.
- **`probe.py`.** Exercised for real on the development machine, since it is
  read-only.
- **Evaluation.** About 30 directories from the development machine with
  hand-labelled expected tiers, run as `pytest -m eval`, reporting per-tier
  agreement and listing every mismatch. This number, not a passing unit suite,
  is what decides whether a later version is allowed to delete anything.

## 10. Configuration and secrets

`TYPESAFE_API_KEY` is read from the environment by the SDK; it is never written
to a run artifact and never present in the privileged probe's environment.
`roots.yaml` and `policy.yaml` ship with defaults and are user-editable. Run
artifacts contain absolute paths from the scanned machine, so `runs/` is in
`.gitignore`.

## 11. Risks

| Risk | Mitigation |
| --- | --- |
| A wrong judgment recommends deleting something valuable | v1 deletes nothing; the safety floor is enforced in code before Jev sees a path; `clean` requires four independent conditions to agree |
| Model judgments drift between versions | the versioned model ID is stamped into each run; thresholds are not carried across versions |
| Adversarial filenames steer a judgment | state is treated as data, not instruction; a wrong answer can only move a row between report tiers, and the eval set includes a hostile-filename case |
| Group evidence is too thin to judge | `unclear` is an explicit option; the escalation pass adds evidence; low confidence routes to `review` |
| Sudo scanning reads sensitive file names | the probe is read-only, stdlib-only, emits names and sizes only, and never leaves the machine except as the filtered state sent to Jev |
| Token cost grows with a large machine | groups are capped per run; a cap breach is reported rather than silently truncated |

## 12. Open questions for a later version

- Should v2 delete directly, or generate a systemd-run sandboxed deletion with a
  restore manifest? Deferred until the evaluation number justifies either.
- Natural-language cleanup intent as a layer over stored judgments.
- Package-manager backends beyond dpkg, snap and docker.
