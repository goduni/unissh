# Getting help with UniSSH

UniSSH is honest, in-progress, anonymously-maintained software. There's no support
desk and no on-call team — but there are good ways to get unstuck. Please go in this
order.

## 1. Read the docs and FAQ first

A lot of common questions are already answered:

- **Docs site:** <https://unissh.dev/>
- **README FAQ / Troubleshooting:** <https://github.com/goduni/unissh#faq--troubleshooting>

Things covered there include the unsigned-build OS warnings ("developer cannot be
verified" / SmartScreen), a client not reaching your server, bootstrap/first-account
problems, the admin panel's `wasm not loaded` message, and `TransportRollback` after a
server restore. Each component also has its own README with platform specifics.

## 2. Questions, support & ideas → Discussions or Telegram

Two places, and the difference between them matters:

- **[GitHub Discussions](https://github.com/goduni/unissh/discussions)** — the canonical
  home. Use it for usage questions, self-host and setup help, "how do I…", and
  open-ended ideas. Answers stay searchable for the next person, which is why anything
  worth answering once belongs here.
- **Telegram — [@unissh](https://t.me/unissh)** — quick questions, release notes, and
  the fastest way to reach other users. Nothing there is archived or searchable, so if a
  Telegram answer turns out to be useful, please repost it as a Discussion.

## 3. Found a bug? → Open an issue

If something is broken and reproducible, open a bug report using the issue form:

- <https://github.com/goduni/unissh/issues/new/choose>

Please include your component, OS/platform, how you installed it, the commit SHA or
tag, what happened vs. what you expected, repro steps, and scrubbed logs. The form
prompts for all of this. Searching [existing issues](https://github.com/goduni/unissh/issues)
first saves everyone time.

Want to fix it yourself? See [`CONTRIBUTING.md`](CONTRIBUTING.md) — contributions of all
sizes are welcome.

## 4. Security issues → report privately, never in public

> [!CAUTION]
> **Do not** open a public issue, PR, or discussion for a suspected vulnerability —
> that discloses it before a fix exists.

Report it privately:

- Email **uni@goduni.me**, or
- Use GitHub's private ["Report a vulnerability"](https://github.com/goduni/unissh/security/advisories/new) advisory form.

The full disclosure policy, scope, and what to expect are in
[`SECURITY.md`](SECURITY.md).

---

**Quick reference**

| I want to… | Go to |
| --- | --- |
| Solve a common problem | [Docs](https://unissh.dev/) + [README FAQ](https://github.com/goduni/unissh#faq--troubleshooting) |
| Ask a question / get setup help / share an idea | [GitHub Discussions](https://github.com/goduni/unissh/discussions) |
| Ask something quickly, or talk to other users | [Telegram @unissh](https://t.me/unissh) |
| Report a reproducible bug | [New issue](https://github.com/goduni/unissh/issues/new/choose) |
| Report a security vulnerability (private) | uni@goduni.me or the [advisory form](https://github.com/goduni/unissh/security/advisories/new) |
| Contribute code or docs | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Support the project | [README § Supporting the project](https://github.com/goduni/unissh#supporting-the-project) |
