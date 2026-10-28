# Git can run code (TRUST-006, TRUST-007)

Coding agents run `git status` and `git diff` in the background as soon as they
open a folder, before you have approved anything. Git reads the repository's own
`.git/config` for those commands, and several of its settings name a program to
run. A repository that reaches you as files with its `.git` folder intact (a
zip, a shared drive, a sync folder) brings that file with it, and the program
runs as you, outside the agent's sandbox. A plain `git clone` does not copy
`.git/config`, so this is about repositories that arrive some other way.

Manifold Security published this in September 2026 as **GitSpawn**: seven
agents, eight flaws, with `core.fsmonitor` as the named setting
([write-up](https://www.manifold.security/blog/ai-coding-agents-git-hijack),
[The Hacker News](https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html)).
Cursor's CVE-2026-26268 is the same idea through `.git/hooks`, and git's own
documentation describes a third shape, a bare repository hidden inside a
project, under `safe.bareRepository`.

mcp-audit checks for all three. **It never runs git** (running git in such a
repository is the attack); it reads a few small files as text.

## Where it runs

| Command | What is checked |
|---|---|
| `mcp-audit scan`, `mcp-audit check` (no path given) | The repository git would use from the current directory, found the way git finds it: walking up to the nearest valid `.git` (a `.git` folder that is not a real git directory is skipped, as git skips it), or a bare repository. This is the GitHub Action's default. |
| `mcp-audit scan --project <dir>` | Every `.git` folder or `.git` file the project walk passes, and every nested bare repository under `<dir>`. |
| `mcp-audit scan --path <file>` | Nothing: an explicit path means "scan exactly this". |

No new flags. The walk keeps skipping the inside of `.git`; mcp-audit reads only:

- `.git/config`, and any file it includes (`include.path`, `includeIf.*.path`)
  that lies inside the scanned folder;
- `.git/config.worktree` and `.git/worktrees/*/config.worktree`, only when
  `extensions.worktreeConfig` is on (git ignores them otherwise, and ignores
  `.git/worktrees/*/config` always);
- a `.git` *file*'s `gitdir:` pointer (submodules, linked worktrees) and the
  `commondir` file it leads to;
- the list of file names in the hooks folder (never their contents);
- `HEAD`, and whether `objects/` and `refs/` exist, to recognise a bare
  repository. `objects/` is never opened.

Reading is capped: 1 MiB per config file and, per repository (config, includes
and worktree configs together), 4 MiB, 20,000 entries and 256 includes. A config
past a cap gets a MEDIUM "too large to inspect fully", because padding a file is
a way to hide keys from a scanner. A secret in a config value (a token echoed by
a credential helper, say) is redacted from every finding.

## TRUST-006: git config runs a command

Git uses the last value of a setting, so a later `core.fsmonitor = false`
switches an earlier command off, and mcp-audit does the same.

| Severity | Setting | When git runs it |
|---|---|---|
| HIGH | `core.fsmonitor` (anything but true/false) | every index refresh: `git status`, `git diff`, `git add`, `git commit` |
| HIGH | `core.sshCommand` | fetch, pull, push to an SSH remote |
| HIGH | `diff.external`, `diff.<driver>.command`, `diff.<driver>.textconv` | `git diff`, `git log -p`, `git show` |
| HIGH | `filter.<driver>.clean` / `smudge` / `process` | add, status, checkout, pull |
| HIGH | `credential.helper` starting with `!`, or naming a program inside the repository (also `credential.<url>.helper`) | whenever git needs a password or token |
| HIGH | `lfs.extension.<name>.clean` / `smudge` (run by git-lfs) | `git add`, `git status` after a tracked LFS file changes, checkout |
| HIGH | `lfs.customtransfer.<name>.path` / `args` when `lfs.standalonetransferagent` (or `lfs.<url>.standalonetransferagent`, any URL) names `<name>` | every fetch, pull, checkout and push that moves LFS objects: git-lfs uses a standalone agent "without asking the server how the transfers should be made" ([git-lfs-config](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-config.adoc)) |
| MEDIUM | `core.editor`, `sequence.editor`, `core.askPass`, `gpg.program`, `gpg.<format>.program`, `merge.<driver>.driver`, `submodule.<name>.update = !…`, `remote.<name>.uploadpack` / `receivepack` | on a git action an agent may take: commit, rebase, signing, merge, submodule update, push |
| MEDIUM | `include.path` / `includeIf.*.path` to a file outside the scanned folder | that file is not read, so whatever it sets is unknown |
| MEDIUM | `core.hooksPath` outside the repository | hooks come from a folder this scan did not look at |
| MEDIUM | `lfs.customtransfer.<name>.path` / `args` (run by git-lfs; `args` is expanded by the shell), not named as the standalone agent | fetch, pull, checkout and push, when the LFS server picks that agent ("Only if the server accepts as a transfer it supports will this custom transfer process be invoked") |
| LOW | `core.pager`, `pager.<command>`, `alias.<name> = !…`, `core.gitProxy` | only on a terminal, or when someone types the alias |
| LOW | `delta.pager` (also a delta feature's `pager`) | when git output is paged through delta, on a terminal |
| INFO | `core.hooksPath` inside the repository | husky and similar tools set this; the hooks are ordinary repo files |

**Tools that write these settings for you are not alarms.** When the command is
one of these tools' own forms, every argument is on that tool's allowlist, and
the program lives outside the repository, mcp-audit lists it once per file as
INFO inventory:

- Git LFS (`git-lfs clean -- %f`, `git-lfs filter-process`; what
  `git lfs install --local` and actions/checkout's `lfs: true` write), git-crypt,
  git-annex, nbstripout (all four keys `nbstripout --install` writes, including
  `"/path/to/python" -m nbstripout` and its `smudge = cat`), nbdime,
  difftastic, rs-git-fsmonitor. The `git lfs …` spelling is not accepted: when
  git-lfs is not installed, git runs `alias.lfs` instead;
- text converters as `diff.<driver>.textconv`: exiftool, docx2txt, pdftotext,
  pandoc, odt2txt, strings, hexdump, xxd, cat, sops, gpg, age, unzip, with
  display options only: for example `pandoc -t plain` with a built-in format
  name (never a `.lua` reader or writer), `exiftool -a -u -g1`, `gpg -d -q
  --batch`, `sops decrypt`, `age -d -i ~/key` (an identity outside the
  repository), `hexdump -C`, `unzip -c -a`. Any other option, including
  `pandoc -o`/`--lua-filter`/`--template`/`--defaults`, ExifTool's `-if`,
  `-config` and `-p` in any letter case, and `gpg --homedir`, keeps the full
  severity. ansible-vault is never known: `ansible-vault view` reads
  `vault_password_file` from an `ansible.cfg` at the repository root, which can
  name a script. Interpreters stay HIGH: `diff.lockb.textconv = bun` (how
  `bun.lockb` was diffed before Bun 1.2) runs any `.js` file `.gitattributes`
  sends it;
- Watchman's setup, `core.fsmonitor = .git/hooks/query-watchman`, when that
  file is an unmodified copy of the `fsmonitor-watchman.sample` git itself ships
  (matched by SHA-256 against every version from git 2.16 to 2.56). An edited
  copy stays HIGH: a payload can sit below a genuine-looking header;
- a plain `ssh` with only key, port, user and known-hosts options
  (`ssh -i ~/.ssh/work_key -F /dev/null`, actions/checkout's `ssh-key:` form);
  any `ProxyCommand`, `LocalCommand`, `-F` config inside the repo or other
  option keeps it HIGH;
- `!gh auth git-credential` (GitHub CLI), gitsign and other signers, common
  editors and pagers with their usual flags (`code --wait`, `vim -f`,
  `emacsclient -t -a ''`, `less -FRX`, `delta --side-by-side`), and
  `merge.<driver>.driver = true`.

**A tool configured in the same file to run something else is not known.**
git-lfs runs programs named in its own section of the git config
(`lfs.extension.<name>.clean`/`smudge`, `lfs.customtransfer.<name>.path`), and
delta runs `delta.pager`. When the repository's config sets one of these, git-lfs
or delta is no longer a fixed program, so `filter.lfs.*` or `core.pager = delta`
keeps the key's full severity. A `delta.pager` that is itself a known pager form
(`less -R`) does not count, and `delta --no-gitconfig` ignores the `[delta]`
section. `.lfsconfig` cannot set these keys (git-lfs reads only a fixed set of
keys from it), so it is not read.

**The arguments are an allowlist, not a deny-list.** Each known tool has a
fixed list of the options it may be given (`_ARG_SPECS` in
`analyzers/git_exec.py`): exact options, options whose value passes a fixed
check (whether written as the next argument, `--opt=value` or attached
`-Xvalue`), fixed subcommand words, and git's `%f`/`%O`/`%A`/`%B` placeholders.
Anything else keeps the key's full severity, and so does any value that names
an existing file or directory in the repository. A deny-list of "options that
load code" was tried first and missed `pandoc -f reader.lua`, `exiftool -IF`,
`exiftool -if2` and `pandoc -o.git/hooks/post-index-change`; the same rule now
also stops `git-lfs merge-driver --program`, `emacsclient -a sh` and
`bat --pager=sh`.

A known tool loses that status if the command contains shell syntax (`|`,
`&&`, `$(…)`, backticks, or a `;` inside quotes: unquoted, git reads `;` as the
start of a comment), or if the program path is inside the repository. A path
inside the repository is judged where it sits, not where a symlink points, so a
repository's `.venv/bin/python` counts as the repository's: it is MEDIUM inside
a real Python environment (one with a `pyvenv.cfg` or `conda-meta/`) and the
full severity anywhere else. For `python -m X`, anything at the repository root
named `X` or `X.*` (`X.py`, `X.pyc`, `X/`, an extension module) keeps the full
severity, because Python would load that copy.

actions/checkout (v6 and later) writes `includeIf.gitdir:…path` entries pointing
at `$RUNNER_TEMP/git-credentials-<uuid>.config`; those produce nothing.

## TRUST-007: repository shapes that run code

| Severity | Shape | Why |
|---|---|---|
| HIGH | A folder not named `.git` that holds `objects/`, `refs/` and a valid `HEAD` (a bare repository) | Git treats the folder itself as a repository when run inside it and reads its `config`. Ordinary projects never contain one. |
| INFO | The same, under a test or fixture folder (`test`, `tests`, `fixtures`, `testdata`, `spec`, …) or in a package manager's dependency cache (SwiftPM `.build/repositories/`, Bundler `vendor/bundle/…/cache/bundler/git/`, Cargo `.cargo/git/db/`, Go `pkg/mod/cache/vcs/`), with a config that runs nothing and no `post-index-change` hook | How git-tooling projects ship test repositories and how those package managers mirror git dependencies. |
| HIGH | An executable `post-index-change` hook | Git runs it whenever it writes the index, and `git status` and `git diff` write it while refreshing file times (checked with git 2.43). |
| INFO | Other executable hooks in the git folder, by the names githooks(5) lists | They run on commit, checkout, merge or push. `.git/hooks` is not in the repository's history, so a copied repository can carry hooks nobody reviewed; pre-commit, husky v4, lefthook and Git LFS install them legitimately. |

A bare folder that a `.git` file points at (the "bare repository plus worktrees"
layout: `.bare/` and `.git` containing `gitdir: ./.bare`) is that repository's own
git folder, not a hidden one. Its config is still checked.

## What to do with a finding

- **HIGH TRUST-006:** if you did not set the key, delete the line with a text
  editor before running git or opening an agent in the folder, then find out
  how it got there. For a one-off git command, override the key:
  `git -c core.fsmonitor=false status`.
- **HIGH TRUST-007:** delete or move the embedded bare repository or the hook
  unless you know why it is there.
  `git config --global safe.bareRepository explicit` stops git from using
  embedded bare repositories at all (the default from Git 3.0).

## Files this adds to the agent execution surface

The git files and directories this reads are listed with the other
repository files agents run or obey, with sources, in
[`docs/agent-execution-surface.md`](agent-execution-surface.md#git-every-harness).

Known limits (attributes not evaluated, `includeIf` conditions not evaluated,
skipped folders, what is not covered) are in [GAPS.md](../GAPS.md).
