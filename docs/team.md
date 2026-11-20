# Credenzo Team

Credenzo Team is a GitHub Action that tells your team when an MCP server, or
one of its tools, changed without review. It runs `credenzo lock --verify`
and, when the check fails, it opens an issue and sends a message to a webhook.

Every `credenzo` command is free under Apache 2.0, and that does not change.
Credenzo Team is the one paid part of the project. You pay for the alerts in
the private repositories of an organization.

## Price

| Repository | Alerts |
|---|---|
| Any repository of a personal account | Free |
| A public repository | Free |
| A private repository of an organization | $99 a month for up to 10 seats |

A seat is a developer who commits to the repositories, or a CI system that
runs the action. The action does not count seats.

With no subscription, the action still runs the check in a private repository
of an organization, and the step still fails on drift. It sends no alert. It
prints one notice in a run where it held an alert back.

## Subscribe

<!-- team-checkout:start -->
Subscriptions are not open yet. Until they open, the action sends alerts for every repository.
<!-- team-checkout:end -->

At checkout, type the name of your GitHub organization (the `acme` in
`github.com/acme`). You can give up to three names. Alerts start within the
hour. You get no licence key and you add no secret for the licence.

To move a subscription to a different organization, cancel it and subscribe
again.

## Set it up

1. Write the lock and commit it ([lock.md](lock.md)):

   ```bash
   credenzo lock
   git add mcp-lock.json && git commit -m "Lock approved MCP servers"
   ```

2. Add the workflow:

   ```yaml
   # .github/workflows/mcp-lock.yml
   name: MCP lock
   on:
     push:
       branches: [main]
     pull_request:
     schedule:
       - cron: "17 6 * * *"

   permissions:
     contents: read
     issues: write

   jobs:
     lock:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: adudley78/credenzo/setup-action@v0.35.0
         - uses: adudley78/credenzo/team@v0.35.0
           with:
             alert-webhook: ${{ secrets.MCP_ALERT_WEBHOOK }}
   ```

   `alert-webhook` is optional. A Slack incoming webhook accepts the message.

## When an alert is sent

| Run | The step | The alert |
|---|---|---|
| Pull request | Fails on drift | None. The failed check is in front of the author. |
| Push, schedule or manual run on the default branch | Fails on drift | One issue, and one webhook message for each new set of findings |
| Push or manual run on another branch | Fails on drift | None. The failed check is in front of the person who pushed. |
| The same check passes again on the default branch | Passes | The issue is closed |

The action keeps one open issue for each check, titled "MCP lock drift". A
check is a workflow, a job, a `path` and the `connect` and `resolve` inputs.
So a scheduled check with `connect` and a check on each push have one issue
each, and a check that passes does not close the issue of the other check.
The action changes the issue when the findings change. The same drift on the
next scheduled run sends nothing new.

The action reads an issue as its own only when the issue was written by the
account of its token (`github-actions[bot]` for the workflow token), or by a
bot account and has the label `credenzo-lock-drift`. An issue that another
person opens is not read, whatever its text.

## A server that changes its tools with no commit

A server can list a new tool tomorrow with no change in your repository. A
check on pull requests does not see that. A scheduled check with `connect`
does: it starts each locked server and compares its tools with the digests in
the lock.

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install 'credenzo[mcp]'
      - uses: adudley78/credenzo/team@v0.35.0
        with:
          connect: "true"
```

Record the tools first with `credenzo lock --connect`. The release binary
cannot connect, so this job installs the package. `connect` runs the servers
that the lock approves; read "Tool definitions" in [lock.md](lock.md) before
you turn it on.

## Inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Project root that holds `mcp-lock.json` |
| `connect` | `false` | Also compare each server's live tools (`lock --verify --connect`) |
| `resolve` | `false` | Also compare floating package versions with the registry (`--resolve`) |
| `alert-issue` | `true` | Keep the drift issue. Needs `issues: write`. |
| `alert-webhook` | none | HTTPS URL that gets `{"text": "..."}` |
| `fail-on-drift` | `true` | Fail the step on drift |
| `github-token` | the workflow token | Token for the issue |

| Output | Meaning |
|---|---|
| `drift` | `true` when the check did not pass |
| `plan` | `personal`, `public`, `licensed`, `preview`, `unchecked` or `unlicensed` |
| `alert` | What the action did about alerts in this run: `opened`, `updated`, `same`, `closed`, `none`, `failed`, `off`, `not on this event` or `not on this branch`, and the result of the webhook |

## What an alert holds

An alert holds finding IDs, severities, server names, tool names, the name of
the check and the link to the run:

```text
MCP lock drift in `acme/app`.

- LOCK-002 (HIGH) `notes`: server is not in the lock
- LOCK-006 (HIGH) `files` tool `delete_all`: tool added
- not verified (entry): `search`

Check: workflow `MCP?lock`, job `lock`, with connect.

Run: https://github.com/acme/app/actions/runs/123
```

A "not verified" line names a server that the check could not compare, for
example a server that did not start. The alert does not hold the reason; the
run log does.

It holds no evidence text, no file path and no config content. A name is cut
to 80 characters, and each character that is not a letter, a digit or one of
`. _ / @ : + -` becomes `?`, so a name in a pull request cannot write a link
or a mention into your issue.

## What leaves the runner

- One GET of the public licence list on the `team-licenses` branch of this
  repository. It is not sent for a personal account or a public repository.
- The issue, in your own repository.
- The webhook message, to the URL that you give.

Nothing is sent to the Credenzo project. The action does not report use.

## How a subscription is found

Twice an hour a workflow in this repository reads the subscriptions from
Stripe and publishes the licence list
([`team-licenses.yml`](../.github/workflows/team-licenses.yml),
[`scripts/team_licenses.py`](../scripts/team_licenses.py)). The action
computes the SHA-256 of `credenzo-team:` plus your owner name in lower case,
and looks for it in the list.

Know these three facts about the list:

- It holds digests, not names. Someone who guesses your organization name
  can compute its digest and see that it is in the list.
- It always holds a multiple of 64 entries. The others are fillers, so the
  length of the list does not show the number of subscribers. The fillers do
  not change. Someone who keeps the copies of the list over time can see
  when an entry is new, and can count the new entries.
- It holds no email address, no Stripe ID and no amount.

When the list cannot be read (GitHub is down, the runner has no network), the
action sends alerts as usual. A network fault never stops an alert. A fault
in an alert (the list, the issue, the webhook) never changes the result of
the step: the result is the exit code of `credenzo lock --verify`.

A subscription whose payment failed keeps its alerts while Stripe tries the
card again.

## Limits

- GitHub Actions only. GitHub Enterprise Server is not tested: the runner
  must reach `raw.githubusercontent.com`.
- The licence check is in open code, under the same Apache 2.0 licence as the
  rest. It is a payment, not a lock: the subscription funds the work.
- The action does not count seats.
- An issue is found again by a marker in its body. If you edit the marker
  out, the next run opens a second issue.
- Use the workflow token or the token of a user for `github-token`. With the
  token of another GitHub App, the action finds its issue again only when
  the issue has the label `credenzo-lock-drift`.
- A server that does not start in a `connect` run is "not verified". That
  opens the issue, and the next run that passes closes it. A server that
  fails now and then gives an issue now and then.
- A tool that writes the date of the day into its text is not drift, when
  the lock was written with Credenzo 0.36.0 or later
  ([lock.md](lock.md#tool-definitions---connect)). Other text that a server
  changes by itself is drift each time.
- The check gets 30 minutes. After that the action stops it and the step
  fails with exit code 2.
- The action follows no redirect.
- The webhook body is `{"text": "..."}` and nothing else.

## Opening subscriptions

For the maintainer. Do these once.

1. In Stripe, make a product "Credenzo Team" with a price of $99 a month,
   and a payment link for it. On the payment link add one custom text field
   with the key `githubowner` and the label "GitHub organization name". Turn
   on the customer portal.
2. In Stripe, make a restricted key that can read Checkout Sessions and
   Subscriptions and nothing else.
3. In this repository, make the environment `team-licenses`, restricted to
   `main`, with two secrets: `STRIPE_API_KEY` (the restricted key) and
   `TEAM_INDEX_SALT` (32 random characters or more; never change it).
4. Record the link and commit the two files that the command changes:

   ```bash
   python3 scripts/team_go_live.py \
       --checkout-url https://buy.stripe.com/... \
       --payment-link-id plink_... \
       --portal-url https://billing.stripe.com/p/login/...
   ```

5. Set the repository variable `TEAM_LICENSES_LIVE` to `true` and run the
   "Team licence list" workflow once.

The 90 days of the experiment start on the date that step 4 records.
`scripts/paid_path_report.py` prints the weekly numbers and the decision.
