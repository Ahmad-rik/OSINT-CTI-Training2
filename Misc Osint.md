Misc OSINT: Techniques Worth Knowing

## Overview

Most investigations are not one clever trick. They are a chain of small, ordinary moves, each of which hands you the next lead: a file that names a user, a user that has a profile, a profile that links to a code account, a repository that remembers something deleted, a wallet, an old web page, a list of wireless networks, a photograph. Any one of these is easy. Knowing that each one exists, what it can and cannot tell you, and how to join them without fooling yourself is the skill.

This module is a tour of those small moves. Each section teaches one technique, then the CTF at the end makes you chain them on an **invented case**. Every person, site, place, wallet and network in the lab is made up.

### The brief

> **TLP:AMBER. Tasking (training scenario; fictional)**
>
> A defaced web page carried a logo, **`tip-off.svg`**. A threat actor is believed to be behind it. That file is all you have.
>
> The commander asks: **who is it, what else can we find out about them, and where are they?**

### What you will learn

- Read what is stored inside a file, and what it reveals about the person who made it.
- Turn a username into a person, and tell the person from the namesake.
- Read a PGP public key as an identity record.
- Recover what was deleted from a repository, and read a wallet on a block explorer.
- Follow a handle that changed, using a web archive.
- Find a real onion address among copies, and read a paste safely.
- Place a Wi-Fi network on a map, and decide between two matches.
- Locate a photograph by what is in it.
- Join all of it into a profile, with a strength for every link.

### Rules

- **Practise on the lab.** Everything in it is invented. On the real internet, work only with authority, for a stated requirement, and no more than the question needs.
- **A username is not a person.** Profiling an adversary is intelligence work. Doing the same to a private individual is surveillance. Know which you are doing.
- **Never use a credential you find.** If a paste or a repository holds a password, record that it exists and move on.
- **Do not contact the target,** and do not log in to anything on their behalf.
- **Grade every link.** A shared key and a shared name are not the same strength. Say which you used.
- **Keep an evidence log:** each page you opened, the time in UTC, and one line on what it told you.

## Setup

You need **Python 3.8 or newer** and a web browser. Nothing else needs installing and nothing needs downloading: everything is in the package, and the lab runs on your own computer. **Nothing in the lab touches the real internet or Tor.**

**Step 1. Open a terminal.** Windows: open the Start menu and type PowerShell. macOS: open Terminal. Linux: open your terminal program.

**Step 2. Check Python.**

```text
Windows:         python --version        (if that fails, try:  py --version)
macOS / Linux:   python3 --version
```

If it is older than 3.8 or missing, install it from python.org (on Windows, tick **"Add python.exe to PATH"**), then **close the terminal and open a new one**. On the commands below, Windows uses `python`; macOS and Linux may need `python3`.

**Step 3. Unpack the package** into a folder you can find, and move into it:

```text
Windows PowerShell:   cd $HOME\Documents\nightjar_misc_osint_ctf_complete
macOS / Linux:        cd ~/Documents/nightjar_misc_osint_ctf_complete
```

**Step 4. Start the lab.**

```text
python start_lab.py
```

```text
Lab running.  Open these in your browser:
  CTF (challenges, hints, scoreboard):  http://127.0.0.1:8080/ctf
  The lab (start here):   http://127.0.0.1:8080/misc
Press Ctrl+C to stop.
```

Leave that window open and **work in your browser**: the CTF page in one tab and the lab in another. If port 8080 is busy, `start_lab.py` says so and suggests another. Your scores are saved in a file, so you can stop and restart without losing them; `python start_lab.py --fresh` starts with an empty scoreboard.

**Step 5. Check (optional).** In a second terminal, in the same folder: `python check_setup.py`. It should report `3 of 3 checks passed`.

### How the CTF works

- Open `/ctf`, enter a **handle**, and choose a challenge. Each has a question, a flag format and two hints.
- A flag is written `FLAG{answer}`. The wrapper is optional, capitals do not matter, and domains may be written defanged. **Underscores matter.**
- A **hint** costs a share of the points: the first 10% and the second 20%. A solved challenge always scores at least a quarter of its points. A wrong flag costs nothing.
- The scoreboard ranks by score and then by who finished first.

> The setup was run from an empty folder on Linux. The Windows and macOS commands are the standard ones for those systems, but I have not run them there. The CTF page's script was run in a simulated browser, not a real one.

#### If something goes wrong

| What you see | Likely cause | What to do |
| --- | --- | --- |
| `python` is "not recognized" | Python is not installed, or not on the PATH | Install it with "Add python.exe to PATH" ticked, or try `py`. Open a new terminal |
| `Port 8080 is already in use` | The lab is already running, or something else has the port | Close the other lab, or use `python start_lab.py 8081` |
| The browser cannot connect | The lab is not running, or you used another port | Start it (Step 4) and use the address it printed |
| The CTF page shows only "Loading..." | JavaScript is switched off | Switch it on for this address: the CTF page needs it |

## 1. Files Tell Stories

A file is more than what you see when you open it. It carries **metadata**: facts the software that made it wrote down. Metadata is often the first lead in an investigation, because the person who made the file rarely knows it is there.

### An SVG is text

An SVG image is not a picture in the way a photograph is. It is a text file written in XML, which the browser draws. That means you can read it. In your browser, put `view-source:` in front of the address, or open the developer tools (F12). The lab's file inspector, on the tour desk, shows the same.

Drawing programs add their own attributes to the file. Inkscape, a common one, has long been documented to record the path of the file on the author's computer, in attributes such as `sodipodi:docname`, `sodipodi:docbase` and `inkscape:export-filename`, and the editor's version number. On Linux and macOS a path usually begins `/home/<name>/` or `/Users/<name>/`, which puts the author's **account name** in the file. Whether a given file contains these depends on the program and its version, so treat it as something to check, not something to expect.

### Photographs: EXIF

A JPEG from a camera or phone carries **EXIF** data: the make and model of the device, the software that wrote the file, the time the picture was taken, and sometimes a **GPS position**. On the command line, `exiftool photo.jpg` prints it all. Many large platforms remove EXIF when you upload a picture, but not all of them do, and a file sent as an attachment or hosted on a small site keeps it.

### What metadata can and cannot tell you

- It tells you what the file *says*, not what is true. Metadata can be edited, copied or forged.
- A username in a path is a **lead**, not proof of identity. Someone else may have made the file on a shared computer.
- A GPS position is where the camera thought it was, at that moment.

### Questions

Answer the questions below to complete this section.

1. Use the file inspector on `skyline.svg`. Does it reveal a path on anyone's computer? What attributes does it list?
2. Use the inspector on `workspace.jpg`. What software wrote the file, and when was the picture taken?
3. Why is a username inside a file a lead and not proof?
4. Name two ways metadata can be missing from a file you were expecting to be rich in it.

## 2. From a Username to a Person

A username is an identifier that people reuse. That is what makes it useful, and what makes it dangerous.

### How to search

- **Start with the exact name.** Search engines usually ignore capitals, so `FrostLantern91` and `frostlantern91` are the same search.
- **Try variants** that people use when a name is taken: with a number, an underscore, a different year.
- **Open every result.** A result's title does not tell you whether the page is about the right person.
- **Use what you find as new searches.** A real name, an e-mail address or a second handle becomes a new lead.

### Linking, and the namesake problem

Many people choose the same popular name. One of the results will be somebody else. Compare the **details**, not the name:

| Signal | Why it helps |
| --- | --- |
| Age, location, language | A teenager in one town is unlikely to be an adult researcher in another |
| Contact details | A different e-mail provider and style is a different person |
| What the account links to | A profile that links to the code account you already have is connected to it |
| Dates | When the account was created and when it was active |
| Photos and interests | Do they fit what you already know? |

Link accounts when something **independent** ties them together, such as a shared link, a shared key or a shared address. Do not link them because the names match.

### Questions

Answer the questions below to complete this section.

1. How many results does the lab's search engine (Findex) give for `lamp oil`? What kind of page is it?
2. Why does searching `frostlantern91` find the same pages as `FrostLantern91`?
3. You find two accounts with the same name. List three kinds of evidence that would justify calling them one person, and one that would not.

## 3. PGP Keys Are Identity Records

People publish **PGP public keys** so that others can send them encrypted messages and check their signatures. A public key is meant to be public, and it carries more than most people think.

### What a public key contains

- **User IDs:** a name and an e-mail address, written by the owner when the key was made. A key can have several, and older ones are often kept.
- **The creation time:** the moment the key was generated.
- **A fingerprint:** a long hash that identifies this key exactly. Its last eight hexadecimal characters are the short **key ID**.
- **The algorithm:** for example RSA or ed25519.

### How to read one

A public key looks like a block of letters between `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----END PGP PUBLIC KEY BLOCK-----`. On your own computer, save it to a file and run:

```text
gpg --show-keys key.asc
```

The lab has a decoder on the tour desk that does the same: paste the whole block and it shows the user IDs, the creation time, the algorithm and the fingerprint. **Only ever paste a public key into a decoder.** A private key must never be pasted anywhere.

### What it means

An address in a user ID is a strong lead: the owner chose it. A second, older user ID is a second lead, and a different domain may reveal a former employer, school or provider. The creation date puts the key in time: a key made years before an incident shows the identity existed then. None of this proves who the person is, but it joins the account to a real mailbox you can search for.

### Questions

Answer the questions below to complete this section.

1. List four things a PGP public key tells you.
2. Why might a key keep an old user ID?
3. Is it safe to paste a private key into an online decoder? Why?
4. What is a key ID, and how is it related to the fingerprint?

## 4. Deleted Is Not Gone: Repository History

A repository keeps every commit, including ones that removed something. A person who pastes a secret into a file, notices, and deletes it has not removed it from the history.

### Reading a history

On a code-hosting site, open the **Commits** page and read the messages. Messages such as "cleanup", "remove config" or "oops" point at a change worth reading. Open the commit: removed lines are in red, added lines in green, and a removed file is marked as such. With git on your own computer:

```text
git log --oneline                      the commits
git log -p                             each commit with its changes
git log -S"stratum"                    only commits where that text was added or removed
git log --diff-filter=D --name-only    commits that deleted files, and which files
git show <hash>                        one commit in full
```

The **older** commit, before the removal, is where the content is. The removing commit shows what was taken out, but the content is also visible in the commit that added it.

### What turns up

Repositories hold e-mail addresses, server names, keys, wallet addresses and credentials that people thought they had removed. A mining configuration has a recognisable shape:

```text
stratum+tcp://WALLET.WORKER:PASSWORD@POOL-HOST:PORT
```

The **wallet** is the account that receives the miner's earnings, the **worker** names the machine, and the **pool** is the service that coordinates the mining and pays out. A wallet address in a public repository ties an identity to a public ledger.

> If you find a working credential, you record that it exists. You never use it.

### Questions

Answer the questions below to complete this section. Use the repositories `frostlantern91/dotfiles` and `frostlantern91/minerkit`.

1. How many commits does `dotfiles` have?
2. `minerkit` is a fork. Of which project, and how far ahead of it is the fork?
3. Why does the commit that *removes* a secret not remove the secret?
4. Name the three parts of a stratum address that identify the owner, the machine and the service.

## 5. Following a Wallet

A **block explorer** is a website that shows a public ledger. Open an address and you see every transaction it was part of: when, how much, in what **coin**, and who paid or received.

### Coins and tokens

A ledger can hold more than one kind of value. The main **coin** is what the network is built on. **Tokens** are other assets that ride on the same ledger, for example a stable currency. An explorer usually separates them, and an address that handles both has done more than mine.

### Payouts and labels

A mining wallet receives small regular payouts from a **pool**. The paying address is often **labelled** on the explorer, because analytics providers tag the addresses of well-known services such as pools and exchanges. The label tells you who paid; the date tells you when. Two pools paying on adjacent days are different pools: read the dates carefully.

### What you can say

You can say that an address received payments from a labelled service on certain dates, in certain coins. That is the wallet's behaviour. It does not tell you the owner's name. In real work, public explorers exist for the common ledgers (Etherscan for Ethereum, for example). The lab's explorer is for an invented coin called LABCOIN.

### Questions

Answer the questions below to complete this section.

1. What is the difference between a coin and a token?
2. A wallet receives money from a labelled pool on 5 May and from a different pool on 6 May. How many pools paid it, and what must you check?
3. A label says "pool payout". Does it tell you the wallet's owner? Why not?

## 6. Handles Change: Web Archives

People rename accounts, move sites, let domains expire and delete posts. A **web archive** keeps copies of pages as they were on particular dates. The best known is the Internet Archive's Wayback Machine. The lab's equivalent is called TimeVault.

### How to use one

Type the address of the page that has gone, and the archive lists the **snapshots** it holds, with dates. Open each one. Compare them: a page that announced a move, an old bio, an earlier version of a profile. Note the **date of the snapshot**, which is when the archive captured the page, not necessarily when it was written.

### Limits

- Archives are incomplete. They hold only pages they were able to capture.
- A snapshot shows the page as it was on the capture date, not as it is.
- An old handle may be reused by someone else later. Check what the account is *now* before you assume.

### Questions

Answer the questions below to complete this section.

1. Why might a snapshot's date be later than the date the page was written?
2. A profile you were given no longer exists. Name two places you can still look for what it said.
3. What risk is there in following an old handle to its current owner?

## 7. Reaching the Dark Web Safely

Module 05 covered how Tor and onion services work and the rules for collecting on them. Here you need only the working practice, applied to a small case.

### Finding an address

Onion addresses are not guessable. You find them on clearnet pages (a link list, a forum thread, a post), and they are often wrong. A link list is user-submitted and unverified, and a copied address can have a typo, or be a look-alike.

### Check before you trust

An onion address is 56 characters of base32, and its last two bytes before the version are a **checksum**. The lab's onion checker (on the tour desk) recomputes it and says **VALID** or **NOT VALID**. A typo fails; a deliberate look-alike passes. So a valid address is necessary, not sufficient: get it from a source you trust, such as the service's own announcement or a checked forum reply.

### Reading a paste

A paste site holds text that someone wanted to share quickly. A list of networks with passwords is a list; **you do not use the passwords**. Record what the paste contains and where it was posted, and who posted it.

### Questions

Answer the questions below to complete this section.

1. Is the address of Ember Search on the lab's onion link list valid? How did you check?
2. A link list and a forum reply give two different addresses for the same service. How do you decide which to trust?
3. You find a list of passwords in a paste. What do you do?

## 8. Wi-Fi as a Location Clue

Every wireless router broadcasts a network name, the **SSID**, and has a hardware address, the **BSSID**. People who drive or walk around recording what they see have built crowdsourced databases that map networks to places. The public service **WiGLE** is the best known (check its current terms and whether a free account is needed for detailed searches). The lab's equivalent is WifiMap.

### How to use it

Search by SSID. The result gives each match's BSSID, its position and when it was first seen. Two things make this harder than it looks:

- **Names repeat.** Many people leave the default name, so a search can return several networks with the same SSID in different places.
- **Positions are where the volunteer was,** which is close to the router but not exact.

### Choosing between matches

Do not guess. Use another clue to decide: the city another network in the same list is named after, the region of other places linked to the person, the date the network was first seen. A match whose position fits the rest of the picture is far likelier than one that does not.

### What names give away

Network names are often named after a town, a street, a hotel or an airport, such as `<CITY>_Free_WiFi`. A list of networks a person has connected to is, in effect, a record of where they have been.

### Questions

Answer the questions below to complete this section.

1. Search the lab's WifiMap for `VESSEN`. How many results, and what is the BSSID and the date first seen?
2. Why can a search for an SSID return several results in different places?
3. Why are the networks in a person's saved list a privacy problem?

## 9. Where Was This Taken?

Geolocation from a picture is a method, not a trick. You list what is in the picture, you search for each clue, and you check each answer against the others.

### The method

1. **List everything.** Landmarks, signs and the language on them, shop names, vehicles, vegetation, the sun, the horizon.
2. **Search the picture itself.** A **reverse image search** (Google Lens, Yandex Images, TinEye, Bing Visual Search) finds pages that contain the same image. Public places such as airport lounges are often photographed and reviewed, so an exact match can name the place at once. The tools differ in quality and change often.
3. **Search the text.** A name on a wall or a sign is a search term.
4. **Use a map.** A screenshot of a map has shapes: a coastline, a lake outline, a road pattern. Match the outline to a known feature, and use any place names on it.
5. **Reason from what you find.** The nearest airport to a landmark, the airport a lounge belongs to, the region of a lake.
6. **Check against everything else.** Does the answer agree with your other clues?

### Pitfalls

- **Confirmation bias.** Do not stop at the first match.
- **Old or staged pictures.** A photo may have been taken years ago, or by someone else.
- **A picture is not a position.** It says where the photographer stood, at that moment.

### Questions

Answer the questions below to complete this section. Use the lab's atlas (the Atlas of Norvald).

1. Which airport is nearest to Brennholm, and how far is it?
2. Which lake has an angular outline with straight sides, Lake Karsa or Lake Orlund? Which airport is nearest to the town of Karsa?
3. A reverse image search returns two pages that show your image. What would you do before trusting the first one?

## 10. Putting a Profile Together

Each technique gave you one fact. The work is joining them honestly.

### Pivot, then verify

A lead from one source becomes a search in another: a username becomes a person, the person becomes an address, the address becomes a key, a key becomes a repository, a repository becomes a wallet. At every step, ask *how sure am I that this is the same person*, and write the answer down.

### Grade the links

| Strength | Examples from this module |
| --- | --- |
| **High** | The same key or address on two accounts; a profile that links to another account; a paste that names an account |
| **Moderate** | Consistent time, place and habits across accounts; a Wi-Fi network near the other places |
| **Low** | A shared name; a similar interest |
| **Not evidence** | A namesake with a different profile |

### Corroborate

Prefer a fact that two independent routes agree on. A home city that comes from a network name, from a Wi-Fi position and from a photo's GPS is far stronger than any one of them.

### Handling the result

Write what you know, how you know it, and what you do not. Label it. Do not publish personal details about a private individual. Report to the people who need it, through the proper channel.

### Questions

Answer the questions below to complete this section.

1. Why is a link that two independent routes support stronger than one that three routes copy from a single source?
2. A profile says someone lives in a city. A photo's GPS and a Wi-Fi match say the same city. What have you gained?
3. What should a profile of a suspected adversary leave out?

## 11. The CTF and the Assessment

You have what you need. Open the CTF page, enter a handle, and start. The questions are on the page; this table lists them by category.

| Category | What it tests | Challenges (points) |
| --- | --- | --- |
| **Files** | Read what is stored inside a file. | F1 It is only text (50); F2 What made it? (50); F3 The camera (50); F4 Where was it taken? (75) |
| **People** | Turn a username into a person, and avoid the namesake. | P1 Search the username (50); P2 The name (50); P3 Same name, other person (75) |
| **Keys** | Read an identity record published as a PGP key. | K1 A key in a repository (50); K2 An older address (75); K3 When was it made? (50); K4 The key ID (75) |
| **Code** | Find what was deleted from a repository. | C1 What was deleted? (75); C2 The commit that removed it (75); C3 The wallet (100); C4 Worker and pool (75) |
| **Money** | Read a wallet on a block explorer. | M1 Coins and tokens (75); M2 Who paid on that day? (75) |
| **Web** | Follow a handle that changed, with an archive. | W1 The current handle (75); W2 When did she say so? (75); W3 Where did she put her notes? (50) |
| **Dark web** | Find a real address among copies; read a paste. | D1 The right address (100); D2 How many networks? (50) |
| **Wi-Fi** | Place a network on a map, and choose between two matches. | WF1 The home network (50); WF2 Its hardware address (100); WF3 Home city (75) |
| **Images** | Locate a picture by what is in it. | I1 Before the flight (100); I2 The layover (100); I3 The lake (100) |
| **Synthesis** | Put the profile together. | S1 One person (100) |

The 29 challenges are worth 2,100 points. Start with Files: everything else leads from what the first file reveals.

> The package you were given contains the lab's data, its answers and a reference solver. Using them would score points and teach you nothing. The point of the CTF is the method.

### The assessment: a profile brief (200 points, graded by a person)

Write one page for the commander. It must contain:

- **A bottom line** of one or two sentences: who the actor is and where they are, and how sure you are.
- **The profile:** names, handles, e-mail addresses, the key, the repositories, the wallet, the networks and the places, each with the page where you found it and the date.
- **The chain:** how each fact led to the next, in order.
- **The links, graded** (high, moderate, low), including who is *not* linked, and why.
- **What you do not know,** and what would settle it.
- **Handling:** a TLP label, defanged addresses, no credentials, and nothing that exposes a private individual.
