# Find crypto usage points

This repository contains demo code for explaining Post-Quantum Cryptography (PQC), Hybrid TLS, and cryptographic inventory.

There is no single application at the repository root. Instead, the repository is organized as a set of independent demos, and you typically build and run each one from its own subdirectory.

This root README focuses on how to use the demo code across the repository.

## Directory overview

| Directory | Purpose | When to use it |
|---|---|---|
| `01-NamedGroups` | Minimal helper for checking JSSE named groups | When you want to inspect the default Java 27 named group ordering |
| `02-TLS_client_server` | Minimal HTTPS/TLSv1.3 sample using only JDK APIs | When you want to explain TLS wiring without Spring |
| `03-HybridTLS-SpringBoot` | Main Spring Boot Hybrid TLS demo | When you want to demonstrate `X25519MLKEM768`, `/api/tls`, and mTLS |
| `04-Audit/crypto-audit-demo` | Cryptographic inventory and audit demo | The main live demo for the 4-layer crypto audit |

## Required tools

JDK 27 should be used for all demos, but if difference between JDK 27 and earlier JDK, you might use JDK 24 or later.

- `03-HybridTLS-SpringBoot` and `02-TLS_client_server` assume **JDK 27**
- `04-Audit/crypto-audit-demo` assumes **JDK 25+**
- Maven 3.9+
- `keytool`
- `curl`
- `bash`
- `openssl` (optional for parts of the audit demo)

## Which demo should I run first?

Recommended order by use case:

1. If you want the main live conference demo, start with `04-Audit/crypto-audit-demo`
2. If you want to show Hybrid TLS through a Spring Boot app, use `03-HybridTLS-SpringBoot`
3. If you want to explain the bare minimum TLS setup in code, use `02-TLS_client_server`
4. If you only want to inspect default named groups, use `01-NamedGroups`

## 01-NamedGroups

This is a minimal helper area for checking the named group order seen by JSSE.

Key things to confirm here:

- On Java 27, `X25519MLKEM768` becomes the preferred first candidate
- The behavior changes if `jdk.tls.namedGroups` is explicitly overridden

This directory is best treated as a supporting check rather than a standalone end-user demo.

## 02-TLS_client_server

This is a Spring-free HTTPS/TLSv1.3 sample built with JDK `HttpsServer` and `HttpClient`.

### Start the server

The simplest option is to launch the source file directly from the directory.

```bash
cd 02-TLS_client_server

java PqcHttpsServer.java
```

By default, it uses `keystore.p12` from the same directory with the password `changeit`, and listens on `https://localhost:8443`.

If you want to override the keystore, use environment variables.

```bash
cd 02-TLS_client_server
export KEYSTORE_PATH="$(pwd)/keystore.p12"
export KEYSTORE_PASSWORD=changeit

java PqcHttpsServer.java
```

### If you still want to build and run it with Maven

```bash
cd 02-TLS_client_server
mvn clean package
java -cp target/classes dev.logicojp.example.PqcHttpsServer
```

### Verify it works

The client code lives in `client/PqcHttpsClient.java` and is designed to validate the server certificate using the truststore. For the simplest connectivity check, you can also use `curl`.

```bash
curl -k https://localhost:8443/
```

This demo is useful when you want to show how TLS is initialized outside of framework abstractions.

## 03-HybridTLS-SpringBoot

This is the main Spring Boot app for demonstrating Hybrid TLS. It exposes `/api/tls` to report request-visible TLS session data, and it includes a Java probe client that can force a specific named group.

### Build

```bash
cd 03-HybridTLS-SpringBoot
mvn clean package
```

### Test

```bash
cd 03-HybridTLS-SpringBoot
mvn test
```

To run a single test class:

```bash
cd 03-HybridTLS-SpringBoot
mvn -Dtest=ApiControllerTest test
```

### Initial setup: generate a local certificate

```bash
cd 03-HybridTLS-SpringBoot
mkdir -p certs

keytool -genkeypair \
  -alias hybrid-tls-demo \
  -keyalg EC \
  -groupname secp256r1 \
  -storetype PKCS12 \
  -keystore certs/server-keystore.p12 \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=localhost, OU=Demo, O=Example, L=Tokyo, S=Tokyo, C=JP" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"
```

### Start the HTTPS server

```bash
cd 03-HybridTLS-SpringBoot
export SERVER_SSL_KEY_STORE="$(pwd)/certs/server-keystore.p12"
export SERVER_SSL_KEY_STORE_PASSWORD=changeit
export SERVER_SSL_KEY_ALIAS=hybrid-tls-demo
export APP_TLS_NAMED_GROUPS="X25519MLKEM768,x25519,secp256r1"

java -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

### Call the API

```bash
curl -k "https://localhost:8443/api/hello?name=Devoxx"
curl -k "https://localhost:8443/api/tls"
curl -k "https://localhost:8443/actuator/health"
```

### Enable SSL handshake logs

If you want to see JSSE SSL/TLS handshake logs, add the JVM option `-Djavax.net.debug=ssl:handshake` when starting either the server or the client.

Server example:

```bash
cd 03-HybridTLS-SpringBoot
java -Djavax.net.debug=ssl:handshake \
  -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

Client example:

```bash
cd 03-HybridTLS-SpringBoot
java -Djavax.net.debug=ssl:handshake \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Debug \
  --named-group X25519MLKEM768 \
  --trust-all
```

### Verify `X25519MLKEM768` deterministically

Constrain the server to a single named group, then use the bundled Java client to offer only that same group.

```bash
cd 03-HybridTLS-SpringBoot
export SERVER_SSL_KEY_STORE="$(pwd)/certs/server-keystore.p12"
export SERVER_SSL_KEY_STORE_PASSWORD=changeit
export SERVER_SSL_KEY_ALIAS=hybrid-tls-demo
export APP_TLS_NAMED_GROUPS="X25519MLKEM768"

java -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

In another terminal:

```bash
cd 03-HybridTLS-SpringBoot
mvn compile

java -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Probe \
  --named-group X25519MLKEM768 \
  --trust-all
```

The key point of this demo is that **JDK 27 JSSE performs the Hybrid TLS key exchange**. The Spring Boot app mainly exposes observable results.

### Try mTLS

For the full certificate generation and truststore flow, see `03-HybridTLS-SpringBoot/README.md`. The general pattern is to start the app with `tls,mtls` profiles and pass `--client-keystore` plus `--truststore` to the client.

## 04-Audit/crypto-audit-demo

This is the main “cryptographic inventory” demo used in the talk. It combines a Spring Boot app with scripts that find cryptographic usage across dependencies, source code, configuration, and runtime behavior.

### Build

```bash
cd 04-Audit/crypto-audit-demo
mvn clean package -DskipTests
```

### First command to run

```bash
cd 04-Audit/crypto-audit-demo
./scripts/crypto-audit.sh .
```

This gives you the static analysis phases of the 4-layer audit in one pass: dependencies, source, configuration, and keystore references.

### Enumerate JCE providers and algorithms

```bash
cd 04-Audit/crypto-audit-demo
java scripts/CryptoAuditJce.java
```

This shows the algorithms registered in the JDK and classifies them as PQC, quantum-vulnerable, or low-risk.

### Audit the keystore

```bash
cd 04-Audit/crypto-audit-demo
java scripts/KeystoreAudit.java src/main/resources/keystore.p12 changeit
```

This inspects the PKCS12 contents, including key type, certificate signature algorithm, and key length.

### Start the demo app

In another terminal, start the Spring Boot app with the `demo` profile.

```bash
cd 04-Audit/crypto-audit-demo
java -jar target/crypto-audit-demo-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=demo \
  --server.ssl.key-store-password=changeit
```

### Run the runtime audit

Attach the JFR-based runtime audit to the running app.

```bash
cd 04-Audit/crypto-audit-demo
jcmd -l | grep crypto-audit-demo
java scripts/CryptoAuditRuntime.java --pid <PID> --duration 30
```

### Generate HTTPS traffic

While the runtime audit is active, send a few HTTPS requests from another terminal so TLS and certificate events are easier to observe.

```bash
curl -k https://localhost:8443/api/health

curl -k -X POST https://localhost:8443/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"demo-user"}'
```

### Offline fallback

For conference use, it is a good idea to prepare fallback artifacts such as `demo-output`. 

## Suggested flow for a live presentation

For a live demo, this order works well:

1. Run `./scripts/crypto-audit.sh .` in `04-Audit/crypto-audit-demo`
2. Run `java scripts/CryptoAuditJce.java`
3. Start the app with the `demo` profile
4. Run `CryptoAuditRuntime.java --pid ...`
5. Use `03-HybridTLS-SpringBoot` afterward if you want to add a focused Hybrid TLS / `X25519MLKEM768` explanation

## Further reading

- `03-HybridTLS-SpringBoot/README.md`: detailed Hybrid TLS demo guide
- `04-Audit/README_ja.md`: Japanese overview of the cryptographic inventory demo
- `04-Audit/crypto-audit-demo/README.md`: detailed guide for the audit app itself
