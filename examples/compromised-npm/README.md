# Sample: trusted npm packages, compromised releases

`package-lock.sample.json` lists one known-compromised release of each of six npm packages. Each was a trusted,
widely used package until an attacker published a malicious version:

| Package | Version | What happened |
|---|---|---|
| `chalk` | 5.6.1 | September 2025: a maintainer's npm account was phished and malicious versions of widely used packages were published. |
| `debug` | 4.4.2 | Same incident as chalk. |
| `@ctrl/tinycolor` | 4.1.1 | September 2025: Shai-Hulud, a self-spreading npm worm. |
| `ua-parser-js` | 0.7.29 | 2021: hijacked account; cryptominer and password stealer. |
| `event-stream` | 3.3.6 | 2018: handed over to a new maintainer who added the malicious `flatmap-stream`. |
| `flatmap-stream` | 0.1.1 | The payload of the event-stream attack, aimed at a cryptocurrency wallet. |

No scanner flags a release like these on the day it is published: the advisory does not exist yet. Once it does,
the next scan flags it. That is the case for scanning on a schedule rather than once at approval.

The published report is at `site/samples/compromised-npm/report.html`. Rebuild it with `./build.sh`. Only the
lockfile is read; nothing is downloaded from npm or installed.
