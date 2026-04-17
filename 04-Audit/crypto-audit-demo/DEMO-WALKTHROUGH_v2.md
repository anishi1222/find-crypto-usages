# Crypto Audit Demo — Presentation Walkthrough & Talk Script (v2)

> **Session:** _Quantum-Ready Java: A Practical Guide to Post-Quantum Cryptography Migration_
>
> **Section:** Inventory — "Where Does Crypto Hide?" (10 minutes)
>
> This document is the step-by-step demo script with English talk track,
> terminal commands, expected outputs, and timing marks.
>
> **v2 changes:** Re-framed around the deck's four-layer model with explicit question
> lines. `CipherSuiteCheck.java` promoted into the core Layer 4 capability path.
> Runtime evidence included as a core-path pre-captured step; live JFR is optional.
> JFR wording softened to match what the packaged recording actually proves.
> Exact negotiated named-group guidance updated: built-in JFR alone is not enough in
> this JDK build; use JSSE handshake debug when you need handshake-level proof of the
> negotiated group.

---

## Table of Contents

1. [Pre-Demo Setup](#1-pre-demo-setup)
2. [Demo Opening — Set the Context](#2-demo-opening--set-the-context)
3. [Layer 1 — Dependencies](#3-layer-1--dependencies)
4. [Layer 2 — Source Code and Frameworks](#4-layer-2--source-code-and-frameworks)
5. [Layer 3 — Configuration and Keystore](#5-layer-3--configuration-and-keystore)
6. [Layer 4 — JVM Capability and Evidence](#6-layer-4--jvm-capability-and-evidence)
   - [6a — Capability: JCE Provider Enumeration](#6a--capability-jce-provider-enumeration)
   - [6b — Capability: TLS Cipher Suites and Named Groups](#6b--capability-tls-cipher-suites-and-named-groups)
   - [6c — Evidence: Pre-Captured Runtime Recording (Core Path)](#6c--evidence-pre-captured-runtime-recording-core-path)
   - [6d — Evidence: Live JFR Capture (Optional / Extended)](#6d--evidence-live-jfr-capture-optional--extended)
   - [6e — Optional: Exact Negotiated-Group Verification](#6e--optional-exact-negotiated-group-verification)
7. [Demo Summary — Bridge to Prioritisation](#7-demo-summary--bridge-to-prioritisation)
8. [Fallback Procedures](#8-fallback-procedures)

---

## 1. Pre-Demo Setup

### Environment Checklist

```bash
# Verify JDK 27+ (recommended for hybrid TLS named groups)
java -version

# Verify Maven
mvn -version

# Navigate to demo directory
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo

# Pre-download dependencies (offline safety)
mvn dependency:resolve -q

# Set script permissions
chmod +x scripts/crypto-audit.sh

# Verify all scripts work
./scripts/crypto-audit.sh . 2>&1 | tail -5
java scripts/CryptoAuditJce.java 2>&1 | tail -5
java ../ciphercheck-demo/CipherSuiteCheck.java 2>&1 | tail -5
```

### Demo Profile Startup Readiness (Must Do)

Before going on stage, verify that the app can start in `demo` profile with HTTPS.

```bash
# from project root
cd ./find-crypto-usages/04-Audit/crypto-audit-demo

# clean build once (avoid stale class/resource surprises)
mvn clean package -q

# verify demo profile startup (20s smoke run)
timeout 20s java -jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar \
	--spring.profiles.active=demo \
	--server.ssl.key-store-password=changeit
```

Expected success markers:

- `The following 1 profile is active: "demo"`
- `Tomcat started on port 8443 (https)`
- `Started PqcDemoApplication`

If startup fails, do not proceed with live demo before fixing this first.

One-liner version:

```bash
cd ./find-crypto-usages/04-Audit/crypto-audit-demo && mvn clean package -q && timeout 20s java -jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar --spring.profiles.active=demo --server.ssl.key-store-password=changeit
```

### Stage-Ready Command Set (Copy/Paste Safe)

Prepare these commands in a note so you can paste quickly during the talk:

```bash
# 1) Full static audit (Layers 1–3)
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
./scripts/crypto-audit.sh --phase-pause .

# 2) Layer 4a — JCE capability inventory
java scripts/CryptoAuditJce.java 2>&1 | tail -20

# 3) Layer 4b — TLS capability (cipher suites + named groups)
cd $HOME/find-crypto-usages/04-Audit/ciphercheck-demo
java CipherSuiteCheck.java

# 4) Layer 4 evidence — pre-captured JFR (core path, no live app needed)
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java scripts/CryptoAuditRuntime.java --file demo-output/pqc-live.jfr

# 5) Start app in demo profile (Terminal A — for live JFR or custom-event capture, optional)
java --add-opens java.base/sun.security.ssl=ALL-UNNAMED \
	-jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar \
	--spring.profiles.active=demo \
	--server.ssl.key-store-password=changeit

# 6) Live JFR capture (Terminal B; PID from jcmd -l — optional)
jcmd -l | grep crypto-audit-demo
java scripts/CryptoAuditRuntime.java --pid <PID> --duration 60
```

### Demo Output Folder Preparation

```bash
mkdir -p demo-output
```

Store all fallback artifacts here before your session:

- `demo-output/crypto-audit-output.txt`
- `demo-output/pqc-live.jfr` (pre-recorded backup — required for core Layer 4 evidence step)
- Optional screenshots of key output sections

The `pqc-live.jfr` recording is used in the core path (Section 6c). Verify it is present before going on stage:

```bash
ls -lh demo-output/pqc-live.jfr
java scripts/CryptoAuditRuntime.java --file demo-output/pqc-live.jfr 2>&1 | tail -10
```

### Terminal Layout

- Full-screen terminal, dark background, white text
- Font size: **20-24pt** (readable from back row)
- Short prompt: set PS1 to just a dollar sign and space
- Resolution: 1920x1080 minimum

---

## 2. Demo Opening — Set the Context

**Time: 0:00 (1 minute)**

### Talk Track

> "Let me show you what I mean with a real example.
>
> Here is a Spring Boot microservice. REST API, JWT authentication, PostgreSQL database.
> You probably have dozens of services like this in your organisation."

### Terminal

```bash
tree src/main/java -L 5
```

### Talk Track (continued)

> "Now — where is the crypto?
>
> Most developers would say: EncryptionService and JwtService. Maybe TLS.
> That is the tip of the iceberg.
>
> I am going to ask four different questions. Each question finds a different class of hidden crypto.
> That is why one grep is never enough.
>
> Let me run the audit and show you what is actually there."

---

## 3. Layer 1 — Dependencies

**Time: 1:00 (2 minutes)**

> **Question this layer answers:** *What crypto enters the service through libraries and drivers?*

### Terminal

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
./scripts/crypto-audit.sh --phase-pause .
```

The script begins running. Layer 1 (dependency scan) output appears first.

### Talk Track (as Layer 1 output scrolls)

> "Layer one — dependencies.
>
> (point to red marker) Nimbus JOSE+JWT — handles JWT signing inside Spring Security.
> Quantum-vulnerable.
>
> (point to yellow markers) Bouncy Castle, Tink, Spring Security, PostgreSQL JDBC — all need review.
>
> Notice PostgreSQL. Your database driver does TLS on every connection.
> Zero crypto code in your app — but it is there.
>
> Seven crypto libraries found. And we have not even looked at the source code yet."

---

## 4. Layer 2 — Source Code and Frameworks

**Time: 3:00 (3 minutes)**

> **Question this layer answers:** *Where does the application ask for crypto, even through framework APIs?*

After you press Enter, Layer 2 output begins.

### Talk Track

> "Layer two — source code and frameworks.
>
> The real crypto is hidden behind framework APIs. Grep alone will miss it.
>
> (point to framework patterns) NimbusJwtEncoder signs JWTs with RSA.
> NimbusJwtDecoder verifies signatures.
> Both are quantum-vulnerable — but grep alone will miss them in your code.
>
> (point to config section) And even here we already see server.ssl in your properties file.
> We will come back to that in Layer three.
> Crypto can be turned on with zero Java code.
>
> (point to keystore refs) Keystore references in configuration — more touchpoints."

### Key Output to Highlight

Point to these specific lines as they appear:

- NimbusJwtEncoder / NimbusJwtDecoder (red, quantum-vulnerable)
- JcaContentSignerBuilder with SHA256withRSA (red)
- server.ssl.* TLS configuration (yellow)
- Datasource with SSL params (yellow)
- Keystore/truststore references (yellow)

---

## 5. Layer 3 — Configuration and Keystore

**Time: 6:00 (1.5 minutes)**

> **Question this layer answers:** *What turns crypto on with no Java code at all?*

Layer 3 output appears.

### Talk Track

> "Layer three — configuration and keystore.
>
> The PKCS12 keystore holds an RSA-2048 server key and an RSA-signed certificate chain.
> That material authenticates HTTPS, and it also supports JWT signing and licence verification.
>
> So this layer tells us that certificate and signature material still needs migration.
> But it does not tell us which TLS named group the JVM negotiated at runtime.
>
> That is exactly why Layer 4 needs two views:
> capability and evidence."

---

## 6. Layer 4 — JVM Capability and Evidence

**Time: 7:30 (1.5 minutes core path)**

> **Question this layer answers:** *What can the JVM use — and what did it actually use under real traffic?*

Layer 4 has two complementary views that must both be shown:

| View | Script | Stage status |
|------|--------|-------------|
| Capability — JCE algorithms | `CryptoAuditJce.java` | Core path |
| Capability — TLS named groups | `CipherSuiteCheck.java` | Core path |
| Evidence — runtime recording | `CryptoAuditRuntime.java --file` | Core path (pre-captured) |
| Evidence — live JFR capture | `CryptoAuditRuntime.java --pid` | Optional / extended |

---

### 6a — Capability: JCE Provider Enumeration

**Time: 7:30 (0.75 minutes)**

### Talk Track

> "Now Layer 4. Two views — capability and evidence.
>
> Let me start with capability: every algorithm registered in this JDK."

### Terminal

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java scripts/CryptoAuditJce.java 2>&1 | tail -20
```

### Talk Track (after output)

> "On this JDK — 365 algorithm services are registered.
> 335 are crypto-relevant: 95 quantum-vulnerable, 87 need attention, 129 are low-risk, and 24 are already post-quantum.
>
> ML-KEM and ML-DSA are here — ready to use.
> The platform already has the tools. We just need to use them.
>
> But this only shows what the JDK supports. It does not prove what the application actually used."

### Key Numbers to Emphasise

- Total registered algorithm services: **365**
- Crypto-relevant: **335** (24 PQ + 95 vulnerable + 87 attention + 129 low-risk)
- Post-Quantum available: **24**
- Quantum-Vulnerable: **95**

---

### 6b — Capability: TLS Cipher Suites and Named Groups

**Time: 8:15 (0.5 minutes)**

### Talk Track

> "One more capability view — TLS specifically.
>
> In TLS 1.3, the cipher suite does not tell you the key exchange group.
> So this is the check that matters."

### Terminal

```bash
cd $HOME/find-crypto-usages/04-Audit/ciphercheck-demo
java CipherSuiteCheck.java
```

### Talk Track (after output)

> "This shows the named groups the platform can negotiate — including X25519MLKEM768,
> the hybrid post-quantum group from JEP 527.
>
> That is the capability view.
> It does not prove what one specific handshake negotiated.
>
> Built-in JFR cannot fill that gap for the named group in this JDK build.
> `jdk.TLSHandshake` gives me the protocol version and cipher suite,
> but not the key exchange group.
> And in TLS 1.3, the cipher suite does not identify the named group.
>
> So if I need the exact negotiated group,
> I use JSSE handshake debug.
> That is the practical path in this walkthrough for confirming the negotiated group.
> For this short demo, I use `CipherSuiteCheck` for capability
> and JFR for runtime evidence.
> Now let me show the evidence view — what actually happened when traffic hit the service."

---

### 6c — Evidence: Pre-Captured Runtime Recording (Core Path)

**Time: 8:45 (0.5 minutes)**

This step uses a pre-recorded JFR file. No live app or PID is required for the core path.

### Talk Track

> "JDK Flight Recorder can capture the crypto operations that actually happen at runtime.
>
> I recorded this while the demo app was serving real HTTPS traffic
> over the demo endpoints.
> Let me replay it."

### Terminal

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java scripts/CryptoAuditRuntime.java --file demo-output/pqc-live.jfr
```

### Talk Track (after output)

> "The recording shows TLS handshakes that actually happened — protocol version,
> cipher suite — and the certificate algorithms we observed on those connections.
>
> This is the difference from the JCE audit: that one shows what is available.
> This one shows what was in use.
>
> One important precision point: in TLS 1.3, the cipher suite in the handshake event
> does not expose the negotiated key exchange group.
> So this recording proves that TLS happened and which ciphers were negotiated,
> but it does not, by itself, prove whether the session used classical X25519
> or hybrid X25519MLKEM768.
> If I need the exact negotiated group,
> I have to leave built-in `jdk.TLSHandshake` and use
> `-Djavax.net.debug=ssl,handshake`.
> That is exactly why we needed CipherSuiteCheck — capability and evidence together.
>
> Depending on the workload that produced the recording, you may also see
> certificate-validation-related events.
> In the current live flow, `/api/health` and `/api/token` are enough to show
> TLS activity, but they do not intentionally trigger an explicit PKIX validation path.
> Security property changes still depend on workload."

### What the packaged recording proves and does not prove

Keep this in mind during the talk:

| Claim | Status in packaged recording |
|-------|------------------------------|
| TLS handshakes observed | ✅ Yes |
| Certificate algorithm observed | ✅ Yes |
| X.509 validation events (`jdk.X509Validation`) | ⚠ Workload-dependent — not part of the current live flow |
| Hybrid TLS (X25519MLKEM768) negotiation proved by built-in `jdk.TLSHandshake` | ❌ Not proved — named group not in `jdk.TLSHandshake` |

Do not claim the packaged recording alone proves a hybrid handshake.
Do not claim the packaged recording includes X.509 validation events unless you have
checked the file and seen them.
If you need the exact negotiated named group in this demo, use
`-Djavax.net.debug=ssl,handshake`.
In the current walkthrough, `/api/health` and `/api/token`
are the live traffic sources for TLS evidence.

---

### 6d — Evidence: Live JFR Capture (Optional / Extended)

**Use only if time permits, in an extended session, or during Q&A**

#### Important: JFR Default Configuration

All security-related JFR events are **disabled by default** in `default.jfc`.
The `CryptoAuditRuntime.java` script enables them programmatically via `rs.enable()`.

If you are using `jcmd JFR.start` with the `profile` or `default` settings instead,
you must either use a custom `.jfc` file or override event settings on the command line.

**Events disabled by default that need enabling:**

```xml
<!-- In default.jfc, these are all enabled=false -->
<event name="jdk.TLSHandshake">
  <setting name="enabled">true</setting>   <!-- default: false -->
  <setting name="stackTrace">true</setting>
</event>
<event name="jdk.X509Validation">
  <setting name="enabled">true</setting>   <!-- default: false -->
  <setting name="stackTrace">true</setting>
</event>
<event name="jdk.X509Certificate">
  <setting name="enabled">true</setting>   <!-- default: false -->
  <setting name="stackTrace">true</setting>
</event>
<event name="jdk.SecurityPropertyModification">
  <setting name="enabled">true</setting>   <!-- default: false -->
  <setting name="stackTrace">true</setting>
</event>
<event name="jdk.Deserialization">
  <setting name="enabled">true</setting>   <!-- default: false -->
  <setting name="stackTrace">true</setting>
</event>
```

**Option A — Use `CryptoAuditRuntime.java` (recommended):**
The script handles event enablement and PID-based live streaming automatically:

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java scripts/CryptoAuditRuntime.java --pid <PID> --duration 60
```

No `.jfc` changes are needed for this mode.

**Option B — Use `jcmd` with event overrides:**

```bash
jcmd <PID> JFR.start name=PQC duration=60s filename=recording.jfr \
  +jdk.TLSHandshake#enabled=true \
  +jdk.X509Validation#enabled=true \
  +jdk.X509Certificate#enabled=true \
  +jdk.SecurityPropertyModification#enabled=true \
  +jdk.Deserialization#enabled=true
```

**Option C — Create a custom `.jfc` file:**

Copy `default.jfc` from your JDK (`$JAVA_HOME/lib/jfr/default.jfc`),
change the five events above to `enabled=true`, and use:

```bash
jcmd <PID> JFR.start name=PQC settings=/path/to/pqc-audit.jfc duration=60s filename=recording.jfr
```

#### Talk Track

> "For the live version, we attach directly to the running JVM and stream security events in real time."

**Precision note:** `CryptoAuditRuntime.java --pid` streams the built-in security events.
It is useful for runtime evidence, but it does **not** by itself prove the exact negotiated
named group. For that, use Section 6e: JSSE handshake debug.

#### JFR Live Recording — Exact Procedure

Use two or three terminals:

- Terminal A: run the Spring Boot app (demo profile)
- Terminal B: run `CryptoAuditRuntime.java --pid ...`
- Terminal C (optional): send HTTPS requests while the runtime stream is active

**Step A — Start app in demo profile (Terminal A)**

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java --add-opens java.base/sun.security.ssl=ALL-UNNAMED \
	-jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar \
	--spring.profiles.active=demo \
	--server.ssl.key-store-password=changeit
```

Wait until you see:

- `Tomcat started on port 8443 (https)`
- `Started PqcDemoApplication`

**Step B — Find PID and start runtime stream (Terminal B)**

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo

# find Java process ID
jcmd -l | grep crypto-audit-demo

# stream 60 seconds of live security events from the target JVM
java scripts/CryptoAuditRuntime.java --pid <PID> --duration 60
```

Expected output includes a line similar to:

- `Mode: Live recording (target JVM)`
- `🔗 TLS: ...` once HTTPS traffic starts flowing

**Step C — Generate HTTPS traffic while recording (Terminal C or browser)**

```bash
# health endpoint hit (repeat a few times)
curl -k https://localhost:8443/api/health

# optional: trigger token endpoint in demo mode
curl -k -X POST https://localhost:8443/api/token \
	-H "Content-Type: application/json" \
	-d '{"username":"demo-user"}'
```

Run these 5-10 times during the 60-second recording window to ensure TLS handshake and crypto activity are visible.

Focus your talk track on:

- negotiated TLS protocol/cipher suites
- certificate algorithm observations
- the difference between "available in JDK" (JCE / named groups) vs "actually used" (JFR runtime)

If deserialization output becomes noisy in `--pid` mode, note that the temporary local JMX management channel can generate a few extra management-related events; the TLS and certificate observations are still from the target JVM.

**Step D — Optional: save a `.jfr` artifact instead of live streaming**

```bash
jcmd <PID> JFR.start name=PQC settings=profile \
	filename=demo-output/pqc-live.jfr duration=60s dumponexit=true \
	+jdk.TLSHandshake#enabled=true \
	+jdk.X509Validation#enabled=true \
	+jdk.X509Certificate#enabled=true \
	+jdk.SecurityPropertyModification#enabled=true \
	+jdk.Deserialization#enabled=true

# while the recording is running
curl -sk https://localhost:8443/api/health
curl -sk https://localhost:8443/api/health

# after the recording finishes
java scripts/CryptoAuditRuntime.java --file demo-output/pqc-live.jfr
```

---

### 6e — Optional: Exact Negotiated-Group Verification

**Use only for Q&A or an extended demo**

This is **not** part of the core 10-minute flow.
If someone asks for the **exact negotiated named group**, make the rule explicit:

- built-in `jdk.TLSHandshake` is not enough in this JDK build
- use `-Djavax.net.debug=ssl,handshake`

### Option A — JSSE handshake debug

### Terminal

```bash
# Terminal A — restart the app with JSSE handshake debug
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java -Djavax.net.debug=ssl,handshake \
	-jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar \
	--spring.profiles.active=demo \
	--server.ssl.key-store-password=changeit 2>&1 | tee /tmp/jsse-handshake.log

# Terminal B — trigger one HTTPS request
curl -sk https://localhost:8443/api/health

# Terminal C — search the debug output for key-share / named-group details
rg -i 'key_share|named group|x25519mlkem768|x25519|secp256r1' /tmp/jsse-handshake.log
```

### Talk Track

> "This is not JFR. This is JSSE handshake debug.
>
> It is noisier, so I would not use it in the core flow.
> But it can show the key-share details that built-in `jdk.TLSHandshake` does not expose.
>
> So if someone asks, 'Was that handshake really hybrid?'
> this is the practical way to confirm it on the current demo app."

---

## 7. Demo Summary — Bridge to Prioritisation

**Time: 9:15 (0.75 minutes)**

### Talk Track

> "So — the summary.
>
> We asked four different questions.
> Each layer found a different class of hidden crypto — and each found things the previous layer missed.
>
> That is why one grep is never enough.
>
> And one more boundary to keep in mind: this four-layer audit covers the JVM itself.
> In production, you still need to extend the inventory to edge TLS,
> managed services, and external identity — those live outside the JVM boundary.
>
> (point to the summary numbers)
>
> We found 22 crypto usage points in one small microservice.
> Most of them were invisible — hidden in framework APIs, config files, and keystores.
>
> Imagine your production system with 50 services.
> That could be over a thousand crypto touchpoints.
>
> The point is not the exact number.
> It is that crypto is everywhere — and most of it is invisible.
>
> You cannot migrate what you cannot find.
> That is why inventory is step one.
>
> Now — not everything needs fixing at once.
> The key is prioritisation. Let me show you how."

(Click to next slide: Prioritisation)

---

## 8. Fallback Procedures

### If Maven fails

```bash
# Show pre-captured output
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
cat demo-output/crypto-audit-output.txt
```

### If JCE script fails

```bash
# Run with explicit Java path
/path/to/your-jdk/bin/java scripts/CryptoAuditJce.java
```

### If CipherSuiteCheck fails

```bash
# Verify path
ls $HOME/find-crypto-usages/04-Audit/ciphercheck-demo/CipherSuiteCheck.java

# Run with explicit Java path
java $HOME/find-crypto-usages/04-Audit/ciphercheck-demo/CipherSuiteCheck.java
```

### If demo profile app startup fails

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
mvn clean package -q
timeout 20s java -jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar \
	--spring.profiles.active=demo \
	--server.ssl.key-store-password=changeit
```

If still failing, switch to pre-captured artifacts:

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
cat demo-output/crypto-audit-output.txt
java scripts/CryptoAuditRuntime.java --file demo-output/pqc-live.jfr
```

### If pre-captured JFR file is missing

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
# verify it exists
ls -lh demo-output/pqc-live.jfr
```

If missing, use `--help` to show what the live version does and describe the recording scenario:

```bash
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java scripts/CryptoAuditRuntime.java --help
```

Say:

> "In production you would run this for 60 seconds during peak traffic.
> It captures TLS handshakes, certificate algorithm observations,
> and any security property changes triggered by that workload — with near-zero overhead.
> The packaged demo recording was made under real HTTPS traffic,
> so it shows TLS activity and certificate algorithm observations.
> X.509 validation events are workload-dependent and are not part of the current live path.
> If I need the exact negotiated named group, I do not rely on built-in JFR alone;
> I switch to JSSE handshake debug."

### If `--pid` mode fails (live JFR only)

```bash
# verify process visible
jcmd -l

# if local attach is blocked, fall back to a file-based capture
jcmd <PID> JFR.start name=PQC settings=profile \
	filename=demo-output/pqc-live.jfr duration=60s dumponexit=true \
	+jdk.TLSHandshake#enabled=true \
	+jdk.X509Validation#enabled=true \
	+jdk.X509Certificate#enabled=true \
	+jdk.SecurityPropertyModification#enabled=true \
	+jdk.Deserialization#enabled=true

# while the recording is running
curl -sk https://localhost:8443/api/health
curl -sk https://localhost:8443/api/health

# then analyse the saved recording
cd $HOME/find-crypto-usages/04-Audit/crypto-audit-demo
java scripts/CryptoAuditRuntime.java --file demo-output/pqc-live.jfr
```

### If terminal font is too small

Use Ctrl+= (Cmd+=) to increase font size, or switch to pre-captured screenshots.

### If demo takes too long

Skip directly to the summary:

> "Due to time, let me jump to the results.
> We found 22 crypto usage points. Most were invisible. Let me explain the prioritisation."

---

## Timing Summary

| Section | Time | Cumulative |
|---------|------|-----------|
| Opening + project structure | 1 min | 1:00 |
| Layer 1: Dependencies | 2 min | 3:00 |
| Layer 2: Source + Frameworks | 3 min | 6:00 |
| Layer 3: Configuration + Keystore | 1.5 min | 7:30 |
| Layer 4a: JCE enumeration (capability) | 0.75 min | 8:15 |
| Layer 4b: CipherSuiteCheck (capability) | 0.5 min | 8:45 |
| Layer 4c: Pre-captured JFR evidence (core) | 0.5 min | 9:15 |
| Summary + bridge | 0.75 min | 10:00 |
| **Total** | **10 min** | |

Layer 4 live JFR capture (Section 6d) is **optional** — use during Q&A or extended sessions.

---

## Scripts Used in This Demo

| Script | Purpose | Stage status | JFR Required |
|--------|---------|-------------|-------------|
| `crypto-audit.sh` | Full static audit (Layers 1–3) | Core | No |
| `CryptoAuditJce.java` | JCE provider enumeration (capability) | Core | No |
| `../ciphercheck-demo/CipherSuiteCheck.java` | TLS cipher suites and named groups (capability) | Core | No |
| `CryptoAuditRuntime.java --file` | JFR runtime audit from pre-captured recording (evidence) | Core | No (reads file) |
| `CryptoAuditRuntime.java --pid` | JFR live runtime audit attached to running JVM (evidence) | Optional | Yes |
| `KeystoreAudit.java` | Detailed keystore inspection | Optional | No |
