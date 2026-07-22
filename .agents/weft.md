---
name: weft
description: Launch and manage Harbor feature builds on the Weft orchestrator (runweft.com) — quick-launch plans, model dependency gates as a feature DAG, and monitor/recover runs.
---

Weft ([runweft.com](https://runweft.com)) is Harbor's **feature-build orchestrator**: it spawns isolated `codebuff-lite` (Claude) agents in containers, each working a **feature** (a DAG of tasks on one shared git branch) against the Harbor repo. We use it to turn an approved `docs/plans/<slug>.md` (+ its `openspec/changes/<slug>/`) into a real PR without babysitting a local agent. This is the outer loop of the workflow in [`.agents/ENTRYPOINT.md`](./ENTRYPOINT.md): `@plan (+ @openspec)` → **launch on Weft** → PR.

> **Update this skill:** if the `weft` CLI surface, the launch invocation, or Harbor's project id below drift from reality, fix this file as part of your change. A stale skill is a bug. The CLI is the source of truth — run `weft agents skill` (the full official guide) and `weft <command> --help` before scripting anything new.

## The binary

Point `WEFT` at your Weft CLI binary (set it via an env var or ensure it is on `$PATH`):

```bash
WEFT=weft            # or the absolute path to your weft binary
$WEFT version
$WEFT health          # server reachability (https://runweft.com)
$WEFT agents skill    # the full official agent guide — read this if unsure
```

Auth + server come from `~/.weft/config.yaml` (`$WEFT config show`) — server `https://runweft.com`, token already set. No per-command flags needed for auth.

## Harbor launch facts (memorize these)

| Fact | Value |
|---|---|
| **Project id** | `<YOUR_WEFT_PROJECT_ID>` |
| Repo | `harbor-auth/harbor` (bound to the project) |
| Base branch | `main` |
| Feature branch (auto) | `weft/<slug>-<shortid>` — never create per-task branches |

> **Which project id?** There may be multiple projects on the server. Set `<YOUR_WEFT_PROJECT_ID>` to Harbor's. Verify by grouping features by `project_id` (`$WEFT features list --json`) and confirming known Harbor features (e.g. `user-audit-trail`, `kms-provider-integration`) live under it.

## ⚠️ The #1 gotcha: do NOT pass `--repo-url` / `--base-branch`

The project already binds the repo and base branch. Passing `--repo-url`/`--base-branch` to `quick-launch` (or `start`) **conflicts with the project config and the feature fails within ~3 s** with an empty task list (an orchestration failure, not an implementation failure). Launch with **only** `--name`, `--description`, `--project-id`, and optionally `--max-parallelism` / `--source-url`. Let the project supply repo + branch.

If a feature shows `failed` seconds after launch with zero tasks, this is almost always the cause — relaunch without those flags.

## Launch a plan (the common case)

Launch **one** plan as a feature. Write a **rich description** — it's the agent's entire brief, so mirror the known-good style: point at the plan file, tell it to run `openspec validate <slug> --strict` and follow `tasks.md`, call out the key design Decisions/invariants, name the target packages, and list the validation suite (ending in `make agent-check`).

```bash
WEFT=weft
HARBOR_PROJ=<YOUR_WEFT_PROJECT_ID>

$WEFT features quick-launch \
  --name 'observability-metrics' \
  --project-id "$HARBOR_PROJ" \
  --max-parallelism 1 \
  --description 'Wave 5 Gate-1 ROOT.

PLAN FILE: docs/plans/observability-metrics.md.
OPENSPEC: openspec/changes/observability-metrics/ — run `openspec validate observability-metrics --strict` and follow tasks.md exactly. Honor design.md Decisions (esp. small-n suppression + cardinality-bound arch test) and spec REQ-001..REQ-005.

IMPLEMENT: aggregate-only, zero-PII counters/histograms. NO PII/quasi-identifier labels (no user_id/ppid/email/ip/subject); enforce bounded label cardinality via an arch test. Targets: internal/telemetry/, internal/oidcapi/, internal/mgmtapi/.

VALIDATION: go build ./..., go vet ./..., go test ./..., and `make agent-check` must be green.'
```

`quick-launch` = `create` + `start` in one call and returns the `feat_…` id. (Split them with `features create` then `features start <id>` only if you need to set up a DAG parent first — see below.)

## Dependency gates → a feature DAG

When plans depend on each other (e.g. Wave 5's `docs/plans/README.md` gate order), model it as a **parent/child DAG** so Weft enforces ordering automatically — a child only starts after its parent completes. **Only launch the roots yourself; Weft starts the dependents.**

```bash
# Gate-1 roots: launch both now (independent DAG roots)
$WEFT features quick-launch --name 'regional-data-residency-routing' --project-id "$HARBOR_PROJ" --description '...'
$WEFT features quick-launch --name 'observability-metrics'          --project-id "$HARBOR_PROJ" --description '...'

# A Gate-2 plan that inherits Gate-1 invariants → child of a root (create, don't quick-launch):
$WEFT features create --name 'user-account-recovery' \
  --parent-feature-id <gate1-feature-id> --project-id "$HARBOR_PROJ" --description '...'
```

Rules: only **leaf** features count toward capacity; parents must complete before children start; set the edge at creation with `--parent-feature-id`. Use `--max-parallelism N` to fan out independent tasks **within** one feature.

**Before launching anything, check it isn't already running or shipped** (avoid duplicate/`failed` clutter):

```bash
$WEFT features list --json | grep -iE 'name|status' | grep -i <slug>   # already live?
$WEFT features list --status completed | grep -i <slug>                 # already shipped?
```

## Monitor a run

```bash
$WEFT features get <feature-id>            # full detail + task list + status
$WEFT features progress <feature-id>       # task counts by status
$WEFT features logs <feature-id>           # lifecycle event log (--limit N)
$WEFT tasks list --feature-id <feature-id> # tasks (--status pending|in_progress|failed|…)
$WEFT agents list                          # connected agents
$WEFT logs -f <agent-id>                   # stream one agent's output live
$WEFT send <agent-id> 'answer/guidance'    # send input to an agent (e.g. unblock a prompt)
```

Feature lifecycle: `proposed → planning → in_progress → reviewing → merging → completed` (or `failed` / `blocked`). A healthy just-launched feature sits in `planning`, **not** `failed`.

## Recover a run

- **`resume <feature-id>`** — keeps completed tasks, resets the rest to pending, re-spawns agents. Use when the task breakdown was right but some tasks failed/stuck.
- **`restart <feature-id>`** — deletes **all** tasks and regenerates from scratch. Use when the original breakdown was wrong.
- **`delete <feature-id>`** — remove a feature entirely (e.g. the inert `failed` duplicates left by a bad `--repo-url` launch).

```bash
$WEFT features resume  <feature-id>
$WEFT features restart <feature-id>
$WEFT features delete  <feature-id>   # clean up dead/duplicate records
```

## Reconcile back to the repo (close the loop)

Weft opens the PR; **you** keep the in-repo memory honest. When a feature merges: promote its plan with **`@plan promote`**, write/reconcile the **`@docs`** feature doc, and (per `@hippo`) drop a `hippo todo` if any follow-up friction surfaced. A shipped feature whose `docs/plans/<slug>.md` still says `status: draft` is drift — fix it.

## Known CLI rough edges

- `features delete --help` / `logs --help` currently **panic** (a cobra flag-shorthand clash on `-f`). The commands themselves work — just skip `--help` for those two and rely on this skill / `weft agents skill`.
- There is **no** top-level `weft projects` command (project scoping is via `--project-id`).
- `weft-agent` (a **different** binary) is what an agent uses *inside* a container to report its own status (`weft-agent task complete`, `weft-agent feature done --pr-url`). As the **operator** driving launches from your workstation, you use `weft`, not `weft-agent`.

## Checklist

- [ ] Using the correct Weft CLI binary (`$WEFT`)?
- [ ] Launching under Harbor's project `<YOUR_WEFT_PROJECT_ID>` (verified)?
- [ ] Launched **without** `--repo-url`/`--base-branch` (project supplies them)?
- [ ] Rich, plan-pointed `--description` (plan file · `openspec validate --strict` · key Decisions/invariants · target packages · validation suite)?
- [ ] Dependency order modeled as a DAG (`--parent-feature-id`); only roots launched by hand?
- [ ] Checked the plan isn't already `planning`/`in_progress`/`completed` before launching?
- [ ] After merge: `@plan promote` + `@docs` reconcile so the plan/feature docs match `main`?
