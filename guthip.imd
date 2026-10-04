
## Overview

People who run malicious infrastructure also write code, and code leaves a record. A public GitHub repository keeps its whole history, including the things its owner later changed, hid or deleted. A GitHub account carries addresses, keys, dates and habits. None of it needs special tools. An investigator does most of this work in a **web browser**, by knowing which page to open and what to look for on it.

This module teaches that, and it is a **CTF**. You get one indicator, a website that behaves like GitHub, and a scoreboard. You find the answers by clicking, reading and comparing, and you submit them as flags.

### The brief

> **TLP:AMBER. Tasking (training scenario; fictional)**
>
> A sandbox report names one network indicator: the domain **`sync.pinewood-cdn.test`**. Someone behind it uses GitHub.
>
> The commander asks: **who are they, what did they leave behind, and what else do they run?**

### What you will learn

- Read a GitHub profile and a repository page the way an investigator does, including the cues that are easy to miss.
- Read a commit properly: who wrote it, who applied it, what address and which time zone it records.
- Use GitHub's search, and know exactly what it cannot see.
- Recover what an owner tried to erase: a commit removed by a force-push and a branch that was deleted.
- Decide which accounts belong together, which only look alike, and how strong each link is.

### How the CTF works

- Open the CTF page in your browser. Enter a **handle** so that your score is kept.
- There are **22 challenges in six categories**. Each has a question, a flag format and two hints.
- A flag is written `FLAG{answer}`. The wrapper is optional, capital letters do not matter, and domains and addresses may be written defanged.
- A **hint** costs a share of the challenge's points: the first costs 10% and the second 20%. However many hints you use, a solved challenge always scores at least a quarter of its points. A wrong flag costs nothing.
- The scoreboard ranks players by score and, when scores are equal, by who finished first.
- The questions depend on each other. A result from one challenge tells you where to look for the next.
- There is also a **write-up**, graded by a person, worth 200 points (see the end of this module).

### The lab and real GitHub

The lab is invented: invented accounts, invented people, addresses from the documentation ranges and `.test` domains. Its website **imitates the structure and the cues of github.com, not its look**. The addresses follow GitHub's, so habits you build here carry over; the pages are plainer; times are shown in UTC where the real site shows your local time; and the lab needs no sign-in for search, which the real site does.

Several cues are real and are taken from GitHub's own behaviour and documentation:

- A commit that no branch contains opens by its hash and carries a banner that reads: *"This commit does not belong to any branch on this repository, and may belong to a fork outside of the repository."*
- The **Activity** view of a repository lists pushes, force pushes, branch creations and branch deletions, ties them to commits and accounts, and offers a "Compare changes" link for each. You can filter it by activity type.
- A commit's `.patch` address shows the author's name, e-mail address and date **with the UTC offset the author's computer recorded**.
- An account's avatar address contains its **account number**.
- Code search needs you to be signed in, indexes only the default branch, and indexes a fork only if it has more stars than the project it was forked from.

### Rules

- **Lab only.** Everything here is invented. On the real GitHub, use public data only, respect the terms and rate limits, and never touch a real person's account in an exercise.
- **A username is not a person.** Tracking an adversary's persona is an intelligence task. Doing the same to a private individual is surveillance. Know which you are doing, have the authority to do it, and collect only what the question needs.
- **Never use a credential you find.** If a repository leaks a token or a password, record that it exists. Do not try it.
- **Grade every link.** An address, a key and a username are not equally strong. Say which one you used.
- **Keep an evidence log:** each page you opened, the time in UTC, and one line on what it told you.

## Setup

You need **Python 3.8 or newer** and a web browser. Nothing else needs installing and nothing needs downloading: everything is in the package, and the lab runs on your own computer.

**Step 1. Open a terminal.** Windows: open the Start menu and type PowerShell. macOS: open Terminal. Linux: open your terminal program.

**Step 2. Check Python.**

```text
Windows:         python --version        (if that fails, try:  py --version)
macOS / Linux:   python3 --version
```

If it is older than 3.8 or missing, install it from python.org (on Windows, tick **"Add python.exe to PATH"**), then **close the terminal and open a new one**. On the commands below, Windows uses `python`; macOS and Linux may need `python3`.

**Step 3. Unpack the package** into a folder you can find, and move into it:

```text
Windows PowerShell:   cd $HOME\Documents\nightjar_github_ctf_complete
macOS / Linux:        cd ~/Documents/nightjar_github_ctf_complete
```

**Step 4. Start the lab.**

```text
python start_lab.py
```

```text
Lab running.  Open these in your browser:
  CTF (challenges, hints, scoreboard):  http://127.0.0.1:8080/ctf
  The investigation (a GitHub-style site):  http://127.0.0.1:8080/github
Press Ctrl+C to stop.
```

Leave that window open. **Do the work in your browser**: keep the CTF page in one tab and the investigation in another. If port 8080 is busy, `start_lab.py` says so and suggests another: use it in the addresses. Stop the lab with Ctrl+C. It listens on your own computer only.

**Step 5. Check (optional).** In a second terminal window, in the same folder:

```text
python check_setup.py
```

```text
Checking your setup (lab address: http://127.0.0.1:8080)

PASS  Python version  (Python 3.12.3)
PASS  GitHub-style site  (the GitHub-style site answers)
PASS  CTF  (22 challenges)

3 of 3 checks passed.  Open  http://127.0.0.1:8080/ctf  in your browser.
```

Your scores are saved in a file, so you can stop the lab and start it again without losing them. `python start_lab.py --fresh` starts with an empty scoreboard.

#### If something goes wrong

| What you see | Likely cause | What to do |
| --- | --- | --- |
| `python` is "not recognized" | Python is not installed, or not on the PATH | Install it with "Add python.exe to PATH" ticked, or try `py`. Open a new terminal afterwards |
| `Port 8080 is already in use` | The lab is already running, or something else has the port | Close the other lab, or use `python start_lab.py 8081` |
| The browser says it cannot connect | The lab is not running, or you used a different port | Start it (Step 4) and use the address it printed |
| The CTF page shows only "Loading..." | JavaScript is switched off in your browser | Switch it on for this address: the CTF page needs it. The investigation pages do not |

> These steps were run from an empty folder on Linux. The Windows and macOS commands are the standard ones for those systems, but I have not run them on those systems. The CTF page's script was run in a simulated browser, not in a real one.

## 1. The Anatomy of a GitHub Page

Everything in this module happens at web addresses. Learn the pattern and you can reach any page without clicking around. In the lab every address starts with `/github`; on the real site, drop that prefix. (The API is the exception: on the real site it lives on its own host, `api.github.com`, and the lab puts it under `/github/api`.)

| Address | What it shows |
| --- | --- |
| `/<user>` | A profile: name, bio, the repositories (forks are labelled "forked from") and its avatar |
| `/<user>.keys` | The account's public SSH keys, one per line, as plain text (empty if there are none) |
| `/<owner>/<repo>` | A repository: files, README, and, for a fork, how far it is ahead of or behind the project it came from |
| `/<owner>/<repo>/commits/<branch>` | The commit list for a branch |
| `/<owner>/<repo>/commits/<branch>/<file>` | The history of one file |
| `/<owner>/<repo>/commit/<hash>` | One commit, with its changes |
| `.../commit/<hash>.patch` and `.diff` | The same commit as plain text, with the author's address and date |
| `/<owner>/<repo>/branches` | The branches that exist now |
| `/<owner>/<repo>/activity` | Pushes, force pushes, branch creations and deletions |
| `/<owner>/<repo>/compare/<a>...<b>` | The commits in `<b>` that are not in `<a>` |
| `/<owner>/<repo>/forks` and `.../network/members` | The forks of a repository |
| `/search?q=<text>&type=code` | Search; the type can be `code`, `repositories`, `users` or `commits` |
| `/api/user/<number>` and `/api/users/<login>` | What GitHub's API answers, opened in the browser as plain text |

### The profile

Open a profile and look at three things. The **Repositories** list shows what the account owns, and a repository that was copied from another project is marked as a fork. The **avatar** is a picture, but its **address** is the point: right-click it and copy the image address. It ends in `/u/<number>?v=4`, and that number is the account's ID, which never changes even if the login does. And the **`.keys` page** shows the public SSH keys the account uses to push code.

### The repository page

Under the title, a fork says **forked from** and names the project it came from. A fork's page also says how far it is from that project, in words like "3 commits ahead of". That is how you separate the fork owner's own work from the history it copied.

### Questions

Answer the questions below to complete this section. Use the innocent practice project at `/github/openbuild/fastpack`.

1. What is the account number of `maya-b`, and where on the page did you find it?
2. What does it mean when an account's `.keys` page is empty?
3. Open `/github/openbuild/fastpack` and list the tabs the repository page offers.

## 2. Reading a Commit

The commit list is the spine of any investigation. Each row shows the message, the author's name, the **account GitHub attaches that address to** (shown as a link), a short hash, and the date. That account is not necessarily the owner of the repository. It is whoever the commit's address belongs to, and the difference will matter.

### The page and the patch

Open a commit. The page shows the changes, with added lines in green and removed lines in red, the parent commit, and a line saying who authored it and when. It shows the date in UTC and **not** the author's e-mail address or UTC offset. For those, add `.patch` to the end of the address.

Take the commit "add progress bar" in `openbuild/fastpack`. The page says:

```text
add progress bar   Ivo N. ( ivo-n )  authored on 2026-03-16 09:15 UTC
```

Its `.patch` address says:

```text
From f05c298c9ccab3c8d7bb35a726d3a7c236ed6801 Mon Sep 17 00:00:00 2001
From: Ivo N. <ivo@openbuild.test>
Date: Mon, 16 Mar 2026 11:15:00 +0200
Subject: [PATCH] add progress bar
```

The same moment, written two ways: 09:15 in UTC, and 11:15 on the author's own clock at **UTC+02:00**. The offset is a clue to where the author's computer thinks it is. It is weak evidence by itself, because it is only a setting, but a lot of commits at the same offset form a pattern.

### Authors, committers and bots

A commit has an **author** (who wrote it) and a **committer** (who applied it). They are often the same. A **bot** has a name ending in `[bot]` and an address that belongs to automation: its commits tell you about the platform, not about a person. And an address in a form like `12345+name@users.noreply.github.com` is a **noreply address**: the number is the account's ID, and the name is the login **at the time the commit was written**.

### The commit that belongs to no branch

A commit can exist without being on any branch, for example after a force-push moved a branch backwards. GitHub still opens it by its hash, and it says so in a banner: *"This commit does not belong to any branch on this repository, and may belong to a fork outside of the repository."* If you ever see that banner, someone changed history, and the commit is worth reading.

### Questions

Answer the questions below to complete this section. Use `openbuild/fastpack`.

1. Who wrote "add progress bar", what address do they use, and what UTC offset does the commit record?
2. How many files, additions and deletions does the commit "release 0.3.0" have?
3. Which page shows an author's e-mail address and UTC offset, and which does not?
4. What does the "does not belong to any branch" banner tell you?

## 3. Searching GitHub

The search box has four types. Choose the type first.

| Type | Finds | Limits |
| --- | --- | --- |
| **code** | Text inside files | Reads only the default branch; does not read new forks; cannot see text that was deleted, or text that is encoded |
| **repositories** | Names and descriptions | Hides forks unless you add `fork:true` |
| **users** | Logins and names | |
| **commits** | Commit messages, authors and addresses | Default branch of each repository; hides forks unless you add `fork:true` |

### Qualifiers

Add qualifiers to the search text to narrow it:

| Qualifier | Meaning |
| --- | --- |
| `user:<login>` or `org:<login>` | Only that account's repositories |
| `repo:<owner>/<repo>` | Only that repository |
| `path:<text>` | Only files whose path contains the text (code search) |
| `author:<login>` | Commits by that account (commit search) |
| `author-email:<address>` | Commits written with that address (commit search) |
| `committer:`, `committer-email:`, `author-name:`, `author-date:`, `hash:` | The same idea for the other fields |

### Why a search finds nothing

When a search returns nothing for a string you know should be somewhere, work down this list:

1. **Try less of it.** A full domain may be stored in a different form, while a shorter piece of it appears in plain text elsewhere.
2. **The text may be encoded.** A string stored as base64 does not match a search for the decoded text. The CTF has an offline decoder page at `/ctf/tools/decode`; your browser's developer console can also decode with `atob("...")`.
3. **It may be deleted.** Search sees only the current files.
4. **It may be on another branch, or in a fork.** Search does not read either. Open the owner's profile and read the repository list yourself.

### Questions

Answer the questions below to complete this section. Use `openbuild/fastpack`.

1. How many commits in `openbuild/fastpack` were written by `ivo-n`? How did you search?
2. How many were written with the address `maya@openbuild.test`?
3. A code search for `progress` finds how many repositories, and in which file?
4. Give two reasons why a code search can return nothing for a string you can see on a repository's page.

## 4. History That Was Erased

People try to hide what they committed by deleting files, deleting branches and rewriting history. GitHub keeps more than they expect, and the page that shows it is **Activity**.

### The history of one file

Add the file name after the commit list: `/commits/main/<file>`. It lists only the commits that changed that file, which is the fastest way to watch a value change over time. Open the commit at the bottom of the list to see how the file began.

### The Activity view

`/<owner>/<repo>/activity` lists what happened to the repository, newest first. The entries are **pushes**, **force pushes**, **branch creations** and **branch deletions**. Use the filters at the top to show only one kind. A **force push** is marked in red and shows the hash the branch pointed at **before** and the hash **after**. The "before" commit is the one that was removed from the branch. A **branch deletion** names the branch and the date, and the Branches page no longer lists it. But the push that **created** that branch is still in Activity, with the commit it contained.

Each push has a **Compare changes** link. For a force push, the "before" hash is the way to open the removed commit: click it, and the page will carry the banner from Section 2.

> In the lab, Activity shows a repository's whole history. On the real site, check how far back it goes before you rely on it.

### Compare

`/compare/<a>...<b>` lists the commits that `<b>` has and `<a>` does not. It works with branches and with hashes, including the hash of a commit no branch contains. Use it to measure what a fork added to the project it was copied from.

### Questions

Answer the questions below to complete this section. Use `openbuild/fastpack`.

1. How many entries does the Activity page of `openbuild/fastpack` list, and of what kind?
2. Which branches does its Branches page list?
3. If a branch were deleted, which page would still show it, and which would not?
4. How do you tell a force push from an ordinary push in the Activity view, and which of its two hashes is the commit that was removed?

## 5. People Behind Accounts

Accounts are linked by evidence, and evidence comes in different strengths.

| Strength | Kind of link | Why |
| --- | --- | --- |
| **High** | The same SSH public key on two accounts | One private key belongs to both |
| **High** | A real e-mail address that GitHub attaches to one account, found in commits in a repository owned by **another** account | The address is verified on one account; using it elsewhere ties the two |
| **High** | The same account **number** in a noreply address | The number survives a rename |
| **Moderate** | A consistent pattern: the same UTC offset in many commits, with working hours that fit | Many people share a time zone. It supports a link, it does not make one |
| **Low** | Similar names, forks, stars | Names are free to copy, and anyone can fork a public repository |
| **Not evidence** | Bot commits, upstream authors in a fork, a shared noreply format | They describe the platform, not the person |

### Comparing keys

Open `/<login>.keys` for each account. Each line is one public key. Compare lines, not words: every key begins with the same `ssh-ed25519`, so look at the **end** of each line. If a line appears on two accounts, they share a key.

### Renamed accounts

A login can change. A commit written before the change still carries the old login inside its noreply address. If you meet a login that no longer exists, take the **number** from the address and open `/api/user/<number>`: the page shows the account's login today.

### Forks and the people around a repository

The **Forks** page lists everyone who copied a repository, with the date. A fork is public and costs nothing, so a fork by itself proves almost nothing. The question is what else ties the fork's owner to the project: a key, an address, or work that appears in both.

### Look-alikes

Attackers and unrelated people both choose names that resemble each other. When two accounts have similar names, ask what ties them **other than the name**: a key, an address, a number, a pattern. If nothing does, you have two accounts that look alike, and linking them would be a mistake that lands on a real person.

### Questions

Answer the questions below to complete this section. Use `maya-b`, `ivo-n` and `jun-t`.

1. What UTC offset does each of them use in `openbuild/fastpack`? What does that say about the team?
2. Do any two of them share a key?
3. How many accounts does a user search for `ivo` return?
4. Two accounts have the same SSH key. What does that tell you, and how strong is it?

## 6. The CTF

You have what you need. Open the CTF page, enter a handle, and start. The questions are on the page; this table lists them by category.

| Category | What it tests | Challenges (points) |
| --- | --- | --- |
| **Recon** | Find the operator's repositories starting from one indicator. | R1 Needle in the haystack (50); R2 The one that got away (50); R3 Whose project? (50) |
| **History** | Read what the commits record, including what was changed later. | H1 First light (50); H2 Rotation (75); H3 Whose commits? (75); H4 The helper (75); H5 Not the operator (50) |
| **Ghosts** | Recover what the owner tried to erase. | G1 Rewritten (100); G2 Deleted (75); G3 What the branch held (100) |
| **People** | Work out who is behind the accounts, and who is not. | P1 Hello, my name is (50); P2 Same address, different house (75); P3 Numbers don't change (75); P4 Locks and keys (75); P5 Copycat? (50); P6 The clock (50); P7 The leak (100) |
| **Network** | Follow forks to the accounts around the repository. | N1 Who forked it? (75); N2 Watching the watchers (50) |
| **Synthesis** | Put it all together. | S1 The infrastructure (200); S2 The accounts (75) |

The 22 challenges are worth 1,625 points. Start with Recon: it gives you the repositories everything else depends on.

> The package you were given contains the lab's data, its answers and a reference solver. Using them would score points and teach you nothing. The point of the CTF is the method.

### The write-up (200 points, graded by a person)

Write one page for a busy commander. It must contain:

- **A bottom line** of one or two sentences.
- **The evidence for each link**, with its strength (high, moderate, low), the page where you found it, and the date.
- **What you could not establish**, for example whether the look-alike account is related, or whether the working pattern is the operator's real one.
- **One graded judgement**, in likelihood and confidence language, on whether the accounts and the infrastructure belong to one operator, with the alternative explanation.
- **Handling:** a TLP label, and nothing that exposes a real person.
