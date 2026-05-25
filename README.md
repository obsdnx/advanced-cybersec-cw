# advanced-cybersec-cw
Hands-on offensive engineering and defensive mitigation of core security vulnerabilities—covering Cryptography, Stack Overflows, XSS/CSP, SQLi, and TCP/IP MITM attacks—implemented within a contained Docker/SEED Linux environment.

# Hands-On Offensive Security & Defensive Mitigation Portfolio

A technical collection of offensive security assessments, exploit development, and defensive engineering mitigations. This project explores low-level systems behavior, software vulnerabilities, and network design weaknesses—moving from initial structural exploitation to complete codebase and configuration-level remediation.

All environments were emulated, tested, and verified within a contained Docker container network inside a SEED Ubuntu Linux VM infrastructure.

---

## 📂 Laboratory Modules

### 🔒 [Lab 1: Secret Key Cryptography](./01-secret-key-crypto/)
* **Core Concepts:** Symmetric Block Ciphers, Initialization Vectors (IVs), Diffusion vs. Confusion, Key Derivation Functions (KDFs).
* **Offensive/Analytical Phase:** * Analyzed structural pattern leakage between `AES-128-ECB` and `AES-128-CBC` modes by investigating visual bitmap pixel artifacts on encrypted images.
  * Successfully broke a monoalphabetic substitution ciphertext using an automated Python character frequency, bigram, and trigram analysis framework.
* **Defensive Phase:** * Evaluated OpenSSL's mandatory `PKCS#7` block padding mechanisms via explicit hexadecimal memory dumps to understand block alignment.
  * Remediated legacy "deprecated key derivation" warnings by implementing `PBKDF2` (Password-Based Key Derivation Function 2) with multi-iteration key stretching and pseudo-random salts to mathematically neutralize offline brute-force optimization.

### 💻 [Lab 2: Stack-Based Buffer Overflows](./02-buffer-overflow/)
* **Core Concepts:** x86/x64 Memory Layouts, Stack Frame Architecture, Frame Pointers (`EBP`), Return Address Hijacking (`RET`), ASLR.
* **Offensive Phase:** Exploited memory safety vulnerabilities in legacy C functions (`strcpy`) to hijack execution flow and spawn root-level shells (`uid=0`). Implemented two distinct exploit scripts:
  1. **Deterministic Offset Attack:** Calculated precise boundary distances between local buffers, the frame pointer, and the target execution frame to inject precise shellcode.
  2. **Return Address Spray Attack:** Constructed a probabilistic multi-offset payload "spray" to cleanly compromise binaries when structural telemetry (like the exact frame pointer position) was missing.
* **Defensive Phase:** Evaluated system-level boundaries (Address Space Layout Randomization, Non-Executable Stack/NX bits) and replaced dangerous unbounded memory operations with robust, bounds-checked primitives (`strncpy`, `snprintf`).

### 🌐 [Lab 3: Cross-Site Scripting (XSS) & Content Security Policy (CSP)](./03-xss-and-csp/)
* **Core Concepts:** Persistent/Stored XSS, Session Hijacking, Cross-Site Request Forgery (CSRF), Self-Propagating DOM Worms, Defenses via CSP Nonces.
* **Offensive Phase:** * Injected functional JavaScript payloads into stateful user profiles to exfiltrate session elements and execute silent, unauthorized actions (modifying target profile context data via asynchronous HTTP requests).
  * Built a weaponized, self-propagating XSS DOM worm capable of autonomously replicating across unique authenticated user sessions upon profile viewing.
* **Defensive Phase:** Designed and verified browser-enforced perimeter constraints. Shifting away from fragile input sanitization logic, implemented strict, cryptographically unique `nonce` attributes within dynamic HTML components and configured robust `Content-Security-Policy` response headers.

### 🗄️ [Lab 4: SQL Injection (SQLi)](./04-sql-injection/)
* **Core Concepts:** Logical Authentication Bypasses, Multi-Statement Injections, Data vs. Code Separation, Prepared Statements.
* **Offensive Phase:** * Executed logical authentication bypasses against vulnerable `SELECT` queries to drop password validation requirements completely and acquire administrative parameters.
  * Injected malicious state variations into unsafe database `UPDATE` routines to alter peripheral data matrices (such as modifying target account profile parameters and salary tables) without legitimate permissions.
* **Defensive Phase:** Completely neutralized SQL logic alteration vectors by refactoring the legacy application layers to use parameterized database layouts via PHP Prepared Statements (`prepare()`, `bind_param()`, and `execute()`).

### 📡 [Lab 5: Packet Sniffing, Spoofing & TCP Session Hijacking](./05-networking-attacks/)
* **Core Concepts:** Promiscuous Mode Eavesdropping, Berkeley Packet Filters (BPF), IP/TCP Header Forgery, Sequence Number Tracking, TCP Session Hijacking.
* **Offensive Phase:** * Leveraged raw Python network sockets utilizing the `Scapy` engine alongside native system utilities (`tcpdump`) to isolate localized interface channels via custom BPF packet captures.
  * Designed a stateful "Sniff-then-Spoof" interceptor framework capable of dynamically calculating legitimate TCP Sequence (`seq`) and Acknowledgment (`ack`) mappings from live traffic.
  * Executed a complete **TCP Session Hijacking Attack** to inject an unauthorized reverse shell command (`/bin/touch /tmp/success`) directly into an active, established Telnet session, successfully demonstrating how asymmetric sequence numbers cause user session desynchronization ("freezing").
* **Defensive Phase:** Evaluated the architectural deficiencies of core legacy internet protocols (lack of intrinsic packet authentication), and analyzed the role of transport-layer encryption (SSL/TLS, SSH) in rendering raw packet injection unfeasible.

---

## 🛠️ Environment, Tools & Languages

* **Operating System & Environments:** Ubuntu Linux (SEED Virtual Machine Framework), Multi-Container Docker Networks.
* **Languages:** Python (Raw Sockets, Scapy Framework, Cryptographic Automation), Bash Scripting, PHP, C, SQL.
* **Security & Inspection Infrastructure:** OpenSSL Engine, `tcpdump` CLI Engine, Wireshark Packet Analyzer, Hexdump Memory Translators.

---

## 🚀 Key Scripts & Execution Highlights

### Executing the Sniff-and-Spoof Framework
To run the automated raw-socket sequence listener and spoofer targeting active TCP/ICMP connections inside the container environment:
```bash
# Navigate to the networking module directory
cd 05-networking-attacks/

# Execute the engine with superuser raw-socket creation privileges
sudo python3 sniff_spoof.py
