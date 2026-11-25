# dsh-cmd-gate

A hard command gate for **DeepSeek Harness (DSH)** shell tools.

It hooks `ctx.tools.guard()` and rejects a command **before it runs**. Not a reminder, not a lint — an execution-time deny that no later layer can override.

Built because "the agent will remember the rule" is not a guarantee. Ten times out of ten it forgets at the moment it matters.

## Rules

| # | Id | Blocks |
|---|----|--------|
| 1 | `sleep` | `sleep` / `Start-Sleep` / `time.sleep(` / `timeout /t` ≥ 20s, including `$t=180; sleep $t` |
| 2 | `long-cmd` | `pip/npm/pnpm/yarn/conda install`, `python -m pip/venv`, `ffmpeg` — unless `run_in_background: true` |
| 3 | `long-timeout` | explicit timeout > 120s (`timeout N`, `--max-time`, `-TimeoutSec`, `timeoutMs`, `TIMEOUT=`, and `arguments.timeoutMs`) |
| 4 | `recursive-delete` | `rm -rf` (`-rfv`/`-fr`/`--recursive`), `rd /s`, `rmdir /s`, `del /s`, `Remove-Item -Recurse`, `find -delete`, `Get-ChildItem \| Remove-Item` |
| 5 | `wide-scan` | `rg` / `grep -r` / `find` / `dir /s` / `Get-ChildItem -Recurse` against `_tools`, `node_modules`, `.git`, drive roots — unless `--glob`-limited or targeting a single file |
| 6 | `repeat` | the same tool with the same arguments 3 times within 90s |
| 7 | `fake-green` | gate scripts (`check_*`, `verify_*`, `selftest`, `closure_check`, `audit_*`) followed by `\|\| echo`, `\|\| true`, `2>/dev/null`, `set +e` |
| 8 | `system-dir` | writes to `C:\Windows`, `Program Files` |
| 9 | `session-log` | writes to `.dsh/sessions` |
| 10 | `git-danger` | `reset --hard`, `checkout -- .`, `clean -f`, `push -f` / `--force` |

Rule 4 exempts `_tmp`, `_归档`, `_备份`, `$TEMP`, and rebuildable dirs (`node_modules`, `__pycache__`, `dist`, `build`, `.venv`, `target`, `cache`).

## Escape hatch

Append `gate-allow` anywhere in the command to let one call through:

```bash
rm -rf ./dist   # gate-allow
```

Use it when quoting these rules in documentation, or when you genuinely mean it. Do not wire it into scripts.

## Install

```bash
# from a DSH profile directory
npm i link:../path/to/dsh-cmd-gate
```

Then add `"dsh-cmd-gate"` to `dsh.profile.bundles` in the profile `package.json` and restart DSH.

The plugin's `cordis.patch.yml` inserts it as `id: cmd-gate`. **`export const name` must equal that id** — not the package name. This is the single most common reason a DSH plugin imports fine but never runs.

## Self-evidence

Everything is logged to a file, so "is it working" is answerable:

```
$TEMP/cmd-gate.log
```

Two things must appear for the gate to be alive:

```
loaded: 命令闸门 v0.3.4 | tools.guard=function
guard registered
```

and any rejection:

```
DENY[recursive-delete] {"tool":"ops_bash"}
```

Override the log path with `CMD_GATE_LOG`.

## Environment

| Var | Default | Meaning |
|---|---|---|
| `CMD_GATE_LOG` | `$TEMP/cmd-gate.log` | log file |
| `CMD_GATE_TRACE` | `$TEMP/gate-trace.on` | if this file exists, every tool call is logged with `callId`/`rootCallId` |

## Design notes

- **Fail open.** If a rule itself throws, the command is allowed. A gate bug must not brick every tool.
- **Strip before matching.** Quotes, here-strings, heredocs, comments, and `$(...)` are removed before rules run, so writing *about* `rm -rf` does not get blocked. Shell `-c "..."` payloads are extracted and checked as subcommands.
- **Performance matters.** The guard runs synchronously on the tool path. Early versions had an O(n²) backtrace on whitespace that froze a session for 20s on an 80KB string; all quantifiers are now bounded and regexes are module-level.
- **`callId === rootCallId`, and parallel calls arrive seconds apart.** The guard sees one call at a time and cannot know how many a step issued — so "one tool per step" is not enforceable here. Rule 6 covers the practical waste instead.

## License

MIT
