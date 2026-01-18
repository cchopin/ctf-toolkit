# CTF Toolkit

Personal repository for CTF challenges, tools, and resources.

## Structure

```
ctf-toolkit/
├── challenges/          # CTF writeups and solutions
│   └── HTB/            # HackTheBox machines
├── cheatsheets/        # Quick reference commands
│   ├── 1-recon/        # Reconnaissance phase
│   ├── 2-exploitation/ # Exploitation techniques
│   ├── 3-escalade/     # Privilege escalation
│   └── 4-post-exploit/ # Post-exploitation
├── payloads/           # Attack payloads by category
│   ├── xss/
│   ├── sqli/
│   ├── lfi/
│   ├── ssti/
│   ├── xxe/
│   ├── ssrf/
│   ├── cmdi/
│   ├── upload/
│   └── deserialization/
├── tools/              # Downloaded tools (gitignored)
└── wordlists/          # Wordlists (gitignored)
```

## Setup

```bash
# Download all tools and wordlists
./setup.sh full

# Force update existing tools
./setup.sh full -f
```

## Tools Installed

- **SecLists** - Collection of security lists
- **rockyou.txt** - Password wordlist
- **PayloadsAllTheThings** - Payload repository
- **PEASS-ng** - Privilege escalation scripts (linpeas, winpeas)
- **Webshells** - PHP/ASP/JSP shells
- **Static binaries** - Precompiled tools for Linux

## Resources

See [resources.md](resources.md) for useful external links.

## Usage

1. Run `./setup.sh full` to download tools
2. Browse `cheatsheets/` for quick commands
3. Use `payloads/` for attack strings
4. Document your CTF solutions in `challenges/`
