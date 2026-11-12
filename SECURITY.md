# Security Policy

This document describes how to report security issues in **python-can**, what is in scope, and how to use the library safely in environments where CAN bus access can affect safety, privacy, or operations (vehicles, industrial control, robotics, medical devices, etc.).

It is informed by review of this repository, CAN/automotive security literature, and common secure-software practices. It is **guidance**, not a certification or warranty.

---

## Table of contents

1. [Reporting a vulnerability](#reporting-a-vulnerability)
2. [Supported versions](#supported-versions)
3. [Security scope](#security-scope)
4. [What python-can is (and is not)](#what-python-can-is-and-is-not)
5. [Threat model for integrators](#threat-model-for-integrators)
6. [CAN and in-vehicle network security context](#can-and-in-vehicle-network-security-context)
7. [Library-specific considerations](#library-specific-considerations)
8. [Secure deployment patterns](#secure-deployment-patterns)
9. [Supply chain and dependencies](#supply-chain-and-dependencies)
10. [Security development practices (maintainers)](#security-development-practices-maintainers)
11. [References and further reading](#references-and-further-reading)

---

## Reporting a vulnerability

**Please do not file public GitHub issues for undisclosed security vulnerabilities.**

### Where to report

| Channel | Use when |
|--------|----------|
| **GitHub Private Vulnerability Reporting (PVR)** | Preferred if enabled on this repository’s Security tab |
| **Upstream [hardbyte/python-can](https://github.com/hardbyte/python-can)** PVR / maintainers | Issues in the core `can` package that also affect upstream |
| **This fork’s maintainers** | Issues specific to this fork (`morphiens/pythoncan`) or deployment context |

If no private channel is available, contact repository maintainers directly with a clear subject line (e.g. `python-can security: <short title>`).

### What to include

- Affected version (e.g. `can.__version__` or PyPI release)
- Platform (OS, Python implementation, backend interface: `socketcan`, `pcan`, `socketcand`, etc.)
- Steps to reproduce (minimal script or CLI invocation)
- Impact (confidentiality / integrity / availability / safety relevance)
- Proof of concept if available (keep it responsible—no live vehicle tests without authorization)

### What to expect

- **Acknowledgement** within a reasonable timeframe (target: **10 business days**; adjust per maintainer capacity)
- Triage and severity assessment
- Coordinated disclosure: agree on a publication date before public disclosure
- Credit to reporters who wish to be named (unless they prefer anonymity)
- A **towncrier** fragment with category `security` in `doc/changelog.d/` for fixed issues (see [development docs](https://python-can.readthedocs.io/en/stable/development.html))

### Out of scope for library vulnerability reports

- Attacks that require **physical OBD/CAN access** you already authorized on a production vehicle (report to the vehicle OEM/program owner)
- Vulnerabilities in **third-party hardware drivers**, `socketcand`, Vector/Kvaser SDKs, or optional extras (`python-can-remote`, etc.)—report to those projects
- Missing **SecOC / CANsec** in Classical CAN (by design at the protocol layer; see below)

---

## Supported versions

| Version line | Security support |
|--------------|------------------|
| **4.x** (current in this tree) | Security fixes for confirmed vulnerabilities in supported backends and core APIs |
| **3.x** | Best-effort only; upgrade to 4.x recommended |
| **2.x and older** | Not supported |

Install from [PyPI](https://pypi.org/project/python-can/) or a verified vendor package. Pin versions in production and verify checksums where your process requires it.

---

## Security scope

### In scope

Security defects in the **python-can** Python package when used as documented:

- Core APIs: `can.Bus`, `can.Message`, `can.Notifier`, loggers/players, configuration loading
- Built-in interfaces under `can/interfaces/` (e.g. `socketcan`, `virtual`, `socketcand`, `udp_multicast`, `slcan`, vendor ctypes bindings)
- CLI entry points: `can_logger`, `can_player`, `can_viewer`, `can_logconvert`
- Unsafe handling of untrusted **files**, **network peers**, or **environment configuration** that leads to code execution, unintended bus transmission, or exploitable crashes **in python-can itself**

### Out of scope (but still your responsibility)

- Security of the **CAN bus**, ECUs, gateways, or OEM networks
- Misuse of APIs to send unauthorized frames to a live vehicle or plant
- Compromise of the **host OS**, Python runtime, or hardware adapters outside this library
- Third-party **plugin interfaces** listed in the documentation as externally maintained

---

## What python-can is (and is not)

**python-can** is a user-space library that abstracts CAN hardware and provides logging, playback, and tooling. It runs with the **privileges of the calling process**—often including direct access to kernel CAN devices (`socketcan`), vendor DLLs, or remote CAN bridges.

It **does not**:

- Authenticate CAN frames on the bus (Classical CAN / CAN FD have **no** native sender authentication in ISO 11898-1)
- Enforce OEM security gateways, SecOC, or IDS rules
- Replace safety processes, homologation, or UN R155 / ISO 21434 programs

Any process that can open a bus can typically **read and inject** traffic permitted by the OS and adapter.

---

## Threat model for integrators

When embedding python-can in a product or toolchain, assume:

| Threat | Relevance |
|--------|-----------|
| **Bus injection / spoofing** | Any holder of a connected interface can send arbitrary IDs (unless lower layers enforce policy) |
| **Replay** | Recorded logs (`ASC`, `BLF`, `SQLite`, etc.) can be replayed unless higher layers use freshness (e.g. SecOC) |
| **Denial of service** | High-rate transmission can flood the bus ([protocol-compliant DoS](https://people.bu.edu/staro/VTC_2016.pdf) is a known CAN weakness) |
| **Remote CAN bridging** | `socketcand`, UDP multicast, serial SLCAN, and remote plugins extend the attack surface to the network |
| **Privilege escalation via native code** | Many backends load **vendor shared libraries** through `ctypes` (`can/ctypesutil.py`) |
| **Sensitive data in logs** | Trace files may contain VIN-related, location, calibration, or cryptographic material from the bus |
| **Supply chain** | Transitive Python and native dependencies must be tracked (OWASP/CISA SBOM guidance) |

UN Regulation **[R155](https://eur-lex.europa.eu/eli/reg/2025/5/oj/eng)** explicitly lists threats such as **CAN flooding**, **malicious internal messages**, and **OBD/diagnostic abuse**—python-can is a capable tool in authorized test beds and a **risk multiplier** if deployed with excessive privileges on production paths.

---

## CAN and in-vehicle network security context

Defense must be **layered** (NIST CSF / NHTSA guidance): Identify, Protect, Detect, Respond, Recover.

### Protocol reality

- **ISO 11898-1** (Classical CAN, CAN FD, CAN XL data link) does **not** provide cybersecurity controls; security is added at higher layers or via extensions ([CiA CCN 2025-09](https://www.can-cia.org/services/publications/can-community-news/09-2025)).
- **AUTOSAR SecOC** adds MAC and freshness for configured PDUs ([AUTOSAR SWS SecOC](https://autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_SecureOnboardCommunication.pdf), [practical overview](https://icanhack.nl/knowledge-base/networks/secure-onboard-communication/)). It does **not** stop a compromised legitimate ECU from sending valid authenticated traffic ([OWASP Automotive Security](https://cheatsheetseries.owasp.org/cheatsheets/Automotive_Security_Cheat_Sheet.html)).
- **CANsec** (CAN XL link-layer security) addresses authentication, integrity, optional encryption, and replay at a lower layer ([Fraunhofer CANsec](https://www.ipms.fraunhofer.de/content/dam/ipms/common/documents/2025/CANsec%20-%20Security%20for%20the%20third%20Generation%20of%20the%20CAN%20Bus_en.pdf), [CAST white paper](https://www.cast-inc.com/blog/white-paper-classical-can-and-can-fd-can-xl-functional-safety-and-security-next-generation)).
- **CANopen (FD) security** (SOFA, SPsec) and **secured gateways** are complementary ([CiA proceedings](https://www.can-cia.org/fileadmin/cia/documents/publications/cnlm/march_2023/cnlm_23-1_p34_implementation_requirements_for_secured_gateways_ken_tindell_canis.pdf)).

### Recommended vehicle / plant controls (not provided by python-can)

1. **Segment** infotainment, telematics, and diagnostics from safety-critical CAN domains ([NHTSA Cybersecurity Best Practices 2022](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf)).
2. **Gateway filtering**: allow only defined IDs, rates, and modes per operational state ([secured gateway requirements](https://www.can-cia.org/fileadmin/cia/documents/publications/cnlm/march_2023/cnlm_23-1_p34_implementation_requirements_for_secured_gateways_ken_tindell_canis.pdf)).
3. **Rate limiting / ID whitelists** at transceiver or ECU level to mitigate flooding ([CAN transceiver security](https://www.can-cia.org/fileadmin/cia/documents/proceedings/2017_elend.pdf), [IVNPROTECT](https://www.scitepress.org/Papers/2023/116053/116053.pdf)).
4. **IDS** at network, service, and vehicle-state layers ([ITU-T X.1375](https://www.itu.int/epublications/publication/itu-t-x-1375-2020-10-guidelines-for-an-intrusion-detection-system-for-in-vehicle-networks), [SAID (USENIX Sec '22)](https://www.usenix.org/system/files/sec22-xue-lei.pdf)).
5. **Protect diagnostics**: UDS security access, disable unnecessary debug on shipped units ([NHTSA §8.1](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf)).
6. **Engineering lifecycle**: ISO/SAE **[21434](https://www.iso.org/standard/70918.html)** and UN **[R155/R156](https://www.vehicle-certification-agency.gov.uk/connected-and-automated-vehicles/cyber-security-and-software-updating/)** for CSMS, TARA, and secure updates.

---

## Library-specific considerations

The following maps **this codebase** to common security concerns. Paths are relative to the repository root.

### 1. Privileged bus access

Opening `can.Bus(...)` attaches to a real controller when configured to do so. Scripts and services should:

- Run under **dedicated least-privilege** accounts
- Use **`vcan0`** / `virtual` for development and CI (as in `.github/workflows/ci.yml` with `test/open_vcan.sh`)
- Never expose bus-opening containers or VMs to untrusted users

### 2. Configuration sources

`can.util.load_config()` merges configuration from, in order: explicit dict → `can.rc` → environment → files including `/etc/can.conf`, `~/.can`, `~/.canrc`, and `CAN_CONFIG` JSON ([`can/util.py`](can/util.py)).

| Source | Risk | Mitigation |
|--------|------|------------|
| `CAN_CONFIG` / `CAN_CONFIG_*` env JSON | `json.loads` on operator-controlled env | Restrict env on shared systems; avoid world-writable service units |
| World-readable config files | Bus channel/interface hijacking | File permissions `0640` or tighter; validate in orchestration |
| CLI `extra_args` → `cast_from_string` | Typed kwargs passed to `Bus()` | Do not pass untrusted strings into `can_logger` / automation |

`cast_from_string` only coerces numbers and booleans; it does not execute code—but **downstream interfaces** may interpret string kwargs dangerously if a backend is buggy.

### 3. Remote and multicast interfaces

| Interface | Notes |
|-----------|--------|
| **`socketcand`** ([`can/interfaces/socketcand/socketcand.py`](can/interfaces/socketcand/socketcand.py)) | Plain TCP ASCII protocol; **no TLS or auth in the protocol**. UDP beacon XML is parsed with `xml.etree.ElementTree`. Treat socketcand hosts as **OT-critical**: firewall port 29536 (default), VPN-only, no Internet exposure. Known native flaws in socketcand itself (e.g. [CVE-2026-37538](https://www.sentinelone.com/vulnerability-database/cve-2026-37538/)) affect the **daemon**, not python-can, but the combined system is at risk. |
| **`udp_multicast`** ([`can/interfaces/udp_multicast/bus.py`](can/interfaces/udp_multicast/bus.py)) | Default multicast groups; **no encryption or authentication**; unreliable ordering. Any host on the LAN segment can inject frames. Scope multicast with TTL/hop limit and network segmentation. |
| **`python-can-remote`** (optional extra) | Use only with documented TLS/mTLS where supported ([can-hub](https://can-hub.io/docs/python/)). |

### 4. Native libraries (`ctypes`)

Vendor backends (PCAN, Kvaser, Vector, IXXAT, etc.) load proprietary `.so` / `.dll` via [`can/ctypesutil.py`](can/ctypesutil.py). Risks:

- **DLL search path** hijacking on Windows
- Memory safety bugs in vendor code becoming **RCE** in your process
- Mitigate: install drivers from official sources, verify hashes, run with minimal privileges, keep firmware/drivers patched

### 5. Logging, playback, and SQLite

- Log formats may store **full frame payloads**—classify files as sensitive; encrypt at rest; restrict ACLs.
- [`can/io/sqlite.py`](can/io/sqlite.py) interpolates `table_name` into SQL DDL/DML. **Do not** pass untrusted `table_name` from users (SQL injection risk). Use default `messages` or a strict identifier allowlist.
- **Playback** (`can.player`) on a live bus is equivalent to injection—gate with procedural controls.

### 6. Message validation

`can.Message(..., check=False)` by default does not validate DLC vs data length ([`can/message.py`](can/message.py)). Invalid frames may be accepted and forwarded to hardware. For fuzzing harnesses, enable `check=True`; for production send paths, validate IDs and payloads against your **application allowlist**.

### 7. Command-line tools

`can_logger`, `can_viewer`, and related tools inherit interface selection from config files and argv. Wrap them in systemd/docker with **read-only bus** where the backend supports it (e.g. can-hub ACLs), or use logger-only workflows.

### 8. Plugin interfaces

Backends loaded via entry points (`can._entry_points`) may execute third-party code at import time. Only install plugins from trusted publishers; audit optional extras in [`pyproject.toml`](pyproject.toml).

---

## Secure deployment patterns

### Development and test

- Prefer **`interface='virtual'`** or **`vcan`**.
- Record traces for replay offline; do not point players at hardware unless intended.
- Add **CAN filters** (`can_filters`) to reduce attack surface and accidental exposure of unrelated IDs.

### Production / workshop

| Practice | Rationale |
|----------|-----------|
| **Isolate** CAN tooling VLAN / bench network | OWASP automotive segmentation |
| **No remote socketcand** without VPN + ACL | Unauthenticated remote bus ([socketcand risk](https://www.sentinelone.com/vulnerability-database/cve-2026-37538/)) |
| **TLS** for any CAN-over-IP gateway | OWASP external connection guidance |
| **Separate** capture (read) from calibration (write) roles | Authorization per operation |
| **Monitor** for anomalous ID rates | UN R155 threat 24.1 (flooding) |
| **Retain logs** without secrets; integrity-protect audit trails | Research on secure CAN logging ([ACM IDS/S-LOG](https://dl.acm.org/doi/pdf/10.1145/3487405.3487650)) |

### Robotics / morphle context

If this fork is used on robot or manufacturing lines:

- Treat CAN like **machine I/O**: interlocks, E-stop, and safety PLCs must not rely solely on bus secrecy.
- Python tooling should not run on safety-rated controllers; use it on supervisory nodes with **read-only** taps where possible.

---

## Supply chain and dependencies

### Runtime dependencies (core)

From [`pyproject.toml`](pyproject.toml): `wrapt`, `packaging`, `typing_extensions`, `msgpack` (non-Windows), `pywin32` (Windows CPython).

### Optional extras

`pyserial`, `python-ics`, vendor-specific packages, `asammdf`, etc. Each expands the attack surface—install only what you need.

### Recommended consumer practices

- Generate and monitor an **SBOM** per release ([CISA SBOM minimum elements](https://www.cisa.gov/sites/default/files/2025-08/2025_CISA_SBOM_Minimum_Elements.pdf), [consumption guide](https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_RECOMMENDED_PRACTICES_FOR_SOFTWARE_BILL_OF_MATERIALS_CONSUMPTION-508.pdf))
- Run **`pip-audit`** or equivalent on locked environments ([PyPA pip-audit](https://github.com/pypa/pip-audit))
- Pin versions; use hash-checking or `uv sync --locked` where applicable ([OWASP dependency management](https://owasp.github.io/DevSecOpsGuideline/2-Process/2-3-Build/2-3-2-Software-Composition-Analysis/2-3-2-2-Dependency-Management-and-Cooldown-Policies/), [pip secure installs](https://github.com/pypa/pip/blob/main/docs/html/topics/secure-installs.md))
- Follow [OWASP Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) for CI/CD and dependency updates ([OWASP Proactive Control C6](https://top10proactive.owasp.org/the-top-10/c6-use-secure-dependencies/))

### Maintainer / release

- CI runs **tox**, **mypy**, **ruff**, **pylint**, **black** across platforms (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml))
- Releases use GitHub Actions to publish to PyPI ([development docs](https://python-can.readthedocs.io/en/stable/development.html))
- Document security fixes via **`doc/changelog.d/<id>.security.md`** (towncrier)

---

## Security development practices (maintainers)

1. **Minimize trust boundaries crossed**—validate lengths and encodings on network parsers (`socketcand` receive buffer, multicast unpack).
2. **Parameterized SQL** for all user-influenced identifiers in SQLite paths.
3. **Defense in depth** for XML/UDP: limit size, reject unexpected tags (already partially done in beacon detection).
4. **Security tests** for config loading edge cases (`test/test_load_config.py`, `test/test_util.py`).
5. **Enable GitHub Private Vulnerability Reporting** and keep this file updated.
6. **Coordinate** with upstream hardbyte/python-can for shared code fixes.

---

## References and further reading

### Vulnerability reporting and open source hygiene

1. [GitHub: Adding a security policy (SECURITY.md)](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/add-security-policy)
2. [Safeguard: How to write a SECURITY.md](https://safeguard.sh/resources/blog/write-a-security-md-for-your-open-source-repo)
3. [GitHub Blog: Maintainer’s guide to vulnerability disclosure](https://github.blog/security/vulnerability-research/a-maintainers-guide-to-vulnerability-disclosure-github-tools-to-make-it-simple/)
4. [python-can: Development & contributing](https://python-can.readthedocs.io/en/stable/development.html)

### Automotive / CAN security

5. [OWASP Automotive Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Automotive_Security_Cheat_Sheet.html)
6. [NHTSA Cybersecurity Best Practices for Modern Vehicles (2022)](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf)
7. [NHTSA Cybersecurity Best Practices (2016)](https://www.nhtsa.gov/sites/nhtsa.gov/files/documents/812333_cybersecurityformodernvehicles.pdf)
8. [UN Regulation No. 155 (cyber security)](https://eur-lex.europa.eu/eli/reg/2025/5/oj/eng)
9. [UK VCA: UN R155 & R156 overview](https://www.vehicle-certification-agency.gov.uk/connected-and-automated-vehicles/cyber-security-and-software-updating/)
10. [ISO/SAE 21434:2021 — Road vehicles cybersecurity engineering](https://www.iso.org/standard/70918.html)
11. [CiA CCN 2025-09 — Security on CAN (SecOC, CANsec, gaps)](https://www.can-cia.org/services/publications/can-community-news/09-2025)
12. [AUTOSAR SWS Secure Onboard Communication (SecOC)](https://autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_SecureOnboardCommunication.pdf)
13. [I CAN Hack: Secure Onboard Communication (SecOC)](https://icanhack.nl/knowledge-base/networks/secure-onboard-communication/)
14. [Secured gateways (Ken Tindell, CiA)](https://www.can-cia.org/fileadmin/cia/documents/publications/cnlm/march_2023/cnlm_23-1_p34_implementation_requirements_for_secured_gateways_ken_tindell_canis.pdf)
15. [Fraunhofer: CANsec for CAN XL](https://www.ipms.fraunhofer.de/content/dam/ipms/common/documents/2025/CANsec%20-%20Security%20for%20the%20third%20Generation%20of%20the%20CAN%20Bus_en.pdf)
16. [CAST: CAN / CAN FD / CAN XL safety and security](https://www.cast-inc.com/blog/white-paper-classical-can-and-can-fd-can-xl-functional-safety-and-security-next-generation)
17. [Evaluation of CAN Bus Security Challenges (PMC)](https://pmc.ncbi.nlm.nih.gov/articles/PMC7219335/)
18. [ITU-T X.1375 — IDS for in-vehicle networks](https://www.itu.int/epublications/publication/itu-t-x-1375-2020-10-guidelines-for-an-intrusion-detection-system-for-in-vehicle-networks)
19. [SAID: State-aware defense against IVN injection (USENIX Sec '22)](https://www.usenix.org/system/files/sec22-xue-lei.pdf)
20. [Protocol-compliant DoS attacks on CAN (VTC 2016)](https://people.bu.edu/staro/VTC_2016.pdf)
21. [Cyber security enhancing CAN transceivers (CiA 2017)](https://www.can-cia.org/fileadmin/cia/documents/proceedings/2017_elend.pdf)
22. [CAN firewall / IDS with secure logging (ACM)](https://dl.acm.org/doi/pdf/10.1145/3487405.3487650)

### Remote CAN and tooling

23. [socketcand project](https://github.com/linux-can/socketcand)
24. [CVE-2026-37538 — socketcand buffer overflow advisory](https://www.sentinelone.com/vulnerability-database/cve-2026-37538/)
25. [can-hub: python-can remote interfaces (TLS/mTLS)](https://can-hub.io/docs/python/)
26. [WOOT '15: Fast and Vulnerable (remote CAN case studies)](https://ian.ucsd.edu/slides/Fast_and_Vulnerable-WOOT15.pdf)

### Software supply chain

27. [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
28. [OWASP Proactive Controls C6: Secure dependencies](https://top10proactive.owasp.org/the-top-10/c6-use-secure-dependencies/)
29. [CISA: Securing the software supply chain (developers)](https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-developers)
30. [CISA: 2025 SBOM minimum elements](https://www.cisa.gov/sites/default/files/2025-08/2025_CISA_SBOM_Minimum_Elements.pdf)
31. [PyPA pip-audit](https://github.com/pypa/pip-audit)
32. [Snyk: python-can package health](https://security.snyk.io/package/pip/python-can)

### Regulatory / EU product context

33. [CiA: EU Cyber Resilience Act and CAN](https://www.can-cia.org/fileadmin/cia/documents/publications/cnlm/march_2026/cnlm_26-1_p8_eu_cyber_resilience_act_and_can_holger_zeltwanger_cia.pdf)
34. [EmSA: CANopen (FD) security gap (SOFA / SPsec)](https://www.can-cia.org/fileadmin/cia/documents/publications/cnlm/september_2026/cnlm_26-3_p30_closing_the_can_security_gap_canopen_fd_security_olaf_pfeiffer_emsa.pdf)

---

## Document history

| Date | Change |
|------|--------|
| 2026-11-12 | Initial comprehensive SECURITY.md for this repository (fork of hardbyte/python-can) |

*This file was created to address the absence of a published security policy noted in community assessments (e.g. [Linux Foundation OpenSSF insights](https://insights.linuxfoundation.org/project/hardbyte-python-can)).*
