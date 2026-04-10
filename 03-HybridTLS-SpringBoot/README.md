# Java 27 Hybrid TLS Spring Boot Demo

Simple Spring Boot REST API for demonstrating **Hybrid TLS over TLS 1.3** on **Java 27**.

This app keeps the application layer intentionally small:

- `GET /api/hello` returns a simple JSON response
- `GET /api/tls` shows what the current request can see about the TLS session
- `/actuator/health` provides a quick health check

The Hybrid TLS behaviour comes from **JDK 27 JSSE**. According to JEP 527, Java 27 TLS 1.3 clients prefer the `X25519MLKEM768` hybrid named group by default.

More precisely, JEP 527 says the default JSSE named group ordering starts with:

```text
X25519MLKEM768, x25519, secp256r1, ...
```

So the **first** default named group for a Java 27 TLS 1.3 client is `X25519MLKEM768`.

## Requirements

- JDK 27
- Maven 3.9+
- `keytool` (included with the JDK)
- `curl` for quick endpoint checks

## Build

```bash
mvn clean package
```

Run the tests only:

```bash
mvn test
```

Run a single test class:

```bash
mvn -Dtest=ApiControllerTest test
```

## Generate a local PKCS12 keystore

Create a self-signed certificate for local HTTPS:

```bash
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

Hybrid TLS does **not** require a post-quantum certificate here. The server certificate stays conventional; the post-quantum part is the **TLS 1.3 key exchange group** negotiated by Java 27.

## Run over HTTPS with the `tls` profile

```bash
export SERVER_SSL_KEY_STORE="$(pwd)/certs/server-keystore.p12"
export SERVER_SSL_KEY_STORE_PASSWORD=changeit
export SERVER_SSL_KEY_ALIAS=hybrid-tls-demo

# Optional: explicitly control the named groups JSSE should prefer.
export APP_TLS_NAMED_GROUPS="X25519MLKEM768,x25519,secp256r1"

java -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

The app listens on `https://localhost:8443` when the `tls` profile is active.

## Call the API

Hello endpoint:

```bash
curl -k "https://localhost:8443/api/hello?name=Devoxx%20France%202026"
```

TLS diagnostics endpoint:

```bash
curl -k "https://localhost:8443/api/tls"
```

Health endpoint:

```bash
curl -k "https://localhost:8443/actuator/health"
```

## What `/api/tls` shows

`/api/tls` reports request-level TLS details that the servlet container exposes, such as:

- whether the request is secure
- the negotiated cipher suite
- the SSL session id
- the current `jdk.tls.namedGroups` system property override, if one was set

This is useful for confirming that the app is actually running over HTTPS and that the Java process was started with the expected Hybrid TLS configuration.

Important: `/api/tls` does **not** introspect the provider's full default named group list. It shows whether your process explicitly overrode JSSE defaults via `jdk.tls.namedGroups`.

## Verifying `X25519MLKEM768`

The most reliable way to verify `X25519MLKEM768` is to run the server with that named group configured and then connect with the included Java probe client, which also enables **only** that one named group.

### 1. Start the server with `X25519MLKEM768` only

```bash
export SERVER_SSL_KEY_STORE="$(pwd)/certs/server-keystore.p12"
export SERVER_SSL_KEY_STORE_PASSWORD=changeit
export SERVER_SSL_KEY_ALIAS=hybrid-tls-demo
export APP_TLS_NAMED_GROUPS="X25519MLKEM768"

java \
  -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

### 2. Compile the probe client

```bash
mvn compile
```

### 3. Connect with the probe client

```bash
java -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Probe \
  --named-group X25519MLKEM768 \
  --trust-all
```

If this succeeds, the client prints the TLS protocol, cipher suite, peer principal, HTTP status, and a verification note.

The key point is that the probe uses `SSLParameters#setNamedGroups(new String[] {"X25519MLKEM768"})`. Since the client offers **only that one named group**, a successful TLS 1.3 handshake means JSSE negotiated `X25519MLKEM768`.

On **Java 27**, a TLS 1.3 client will normally **prefer** `X25519MLKEM768` by default even without `--named-group`. However, that is still only a preference:

- the peer must support the same hybrid group
- no library or application code must have overridden the default named group list
- no `jdk.tls.namedGroups` setting must have changed the order

So if you omit `--named-group`, Java 27 will often negotiate `X25519MLKEM768`, but it is **not guaranteed**. The `--named-group X25519MLKEM768` option is there to make the verification deterministic.

## Checking the default JSSE named group order

There are three different questions you might want to answer:

1. What does JDK 27 document as the default order?
2. What is the default order in this exact JVM?
3. What did this specific TLS handshake actually offer or negotiate?

### 1. Check the documented default

JEP 527 documents the Java 27 default named group ordering as:

```text
X25519MLKEM768, x25519, secp256r1, secp384r1, secp521r1, x448,
ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
```

So the default **first** named group is `X25519MLKEM768`.

### 2. Print the default order from the running JVM

If you want to inspect the default order from the current JVM, use `SSLParameters#getNamedGroups()` on a connection-populated or default JSSE parameter object.

This project includes a small helper class for that:

- `dev.logicojp.example.pqchybridtls.tools.PrintDefaultNamedGroups`

Compile and run it with the same JDK 27 build you use for the demo:

```bash
mvn compile

java -cp target/classes \
  dev.logicojp.example.pqchybridtls.tools.PrintDefaultNamedGroups
```

The helper prints:

- the current Java runtime version
- whether `jdk.tls.namedGroups` was explicitly overridden
- the effective named group order seen by JSSE
- the first named group in that order

If you have **not** set `-Djdk.tls.namedGroups=...`, the first element should be `X25519MLKEM768`.

### 3. Check what a real handshake offered or negotiated

If you want to see what happened in a real TLS 1.3 handshake, use JSSE debug logs:

```bash
java -Djavax.net.debug=ssl:handshake \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Debug \
  --trust-all
```

In the output, look for lines that show either:

- the offered `supported_groups`
- the selected or used named group

For example, look for `X25519MLKEM768` in the handshake output.

### Avoid false positives when checking defaults

If you want to inspect the **default** JSSE order, do **not** do any of these:

- do not set `APP_TLS_NAMED_GROUPS`
- do not pass `-Djdk.tls.namedGroups=...`
- do not use `--named-group ...` with `HybridTlsClient`

Those options override the default list, which is useful for deterministic testing, but no longer tells you what the JVM default was.

The probe client already forces **TLS 1.3** in code via `SSLParameters#setProtocols(new String[] {"TLSv1.3"})`. If you also want to constrain the JVM from the command line, you can add:

```bash
-Djdk.tls.client.protocols=TLSv1.3
```

For example:

```bash
java -Djdk.tls.client.protocols=TLSv1.3 -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Probe \
  --named-group X25519MLKEM768 \
  --trust-all
```

### 4. Optional: emit the named group in JSSE debug logs

If you want the named group to appear explicitly in logs, enable handshake debug on either side:

```bash
java \
  -Djavax.net.debug=ssl:handshake \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Probe \
  --named-group X25519MLKEM768 \
  --trust-all
```

or:

```bash
java -Djavax.net.debug=ssl:handshake \
  -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

In those logs, look for `X25519MLKEM768` during the TLS 1.3 handshake.

## JSON output mode

If you want machine-readable results, add `--output json`:

```bash
java -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/tls \
  --named-group X25519MLKEM768 \
  --trust-all \
  --output json
```

The JSON output includes the TLS protocol, cipher suite, peer principal, named group requested by the client, trust mode, response body, and a verification result flag.

## Mutual TLS verification

### 1. Generate a client certificate and trust stores

Export the existing server certificate:

```bash
keytool -exportcert \
  -alias hybrid-tls-demo \
  -keystore certs/server-keystore.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -rfc \
  -file certs/server-cert.pem
```

Create a client certificate:

```bash
keytool -genkeypair \
  -alias hybrid-tls-client \
  -keyalg EC \
  -groupname secp256r1 \
  -storetype PKCS12 \
  -keystore certs/client-keystore.p12 \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=hybrid-client, OU=Demo, O=Example, L=Tokyo, S=Tokyo, C=JP"
```

Export the client certificate and build the trust stores:

```bash
keytool -exportcert \
  -alias hybrid-tls-client \
  -keystore certs/client-keystore.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -rfc \
  -file certs/client-cert.pem

keytool -importcert \
  -alias hybrid-tls-client \
  -file certs/client-cert.pem \
  -keystore certs/server-truststore.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -noprompt

keytool -importcert \
  -alias hybrid-tls-server \
  -file certs/server-cert.pem \
  -keystore certs/client-truststore.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -noprompt
```

### 2. Start the server with the `mtls` profile

```bash
export SERVER_SSL_KEY_STORE="$(pwd)/certs/server-keystore.p12"
export SERVER_SSL_KEY_STORE_PASSWORD=changeit
export SERVER_SSL_KEY_ALIAS=hybrid-tls-demo
export SERVER_SSL_TRUST_STORE="$(pwd)/certs/server-truststore.p12"
export SERVER_SSL_TRUST_STORE_PASSWORD=changeit
export APP_TLS_NAMED_GROUPS="X25519MLKEM768"

java -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls,mtls
```

### 3. Connect with the client certificate and JSON output

```bash
java -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/tls \
  --named-group X25519MLKEM768 \
  --truststore certs/client-truststore.p12 \
  --truststore-password changeit \
  --client-keystore certs/client-keystore.p12 \
  --client-keystore-password changeit \
  --output json
```

If the server returns a successful `/api/tls` response and the JSON output shows `"clientCertificateConfigured": true`, you have verified both:

- `X25519MLKEM768` was forced on the client side
- a client certificate was presented for mutual TLS

For an additional server-side check, inspect the `/api/tls` response body and confirm that `clientCertificateSubject` is populated.

## Project structure

```text
src/main/java/dev/logicojp/example/pqchybridtls/
├── PqcHybridTlsApplication.java      # Bootstraps Spring Boot and maps APP_TLS_NAMED_GROUPS -> jdk.tls.namedGroups
├── api/ApiController.java            # REST endpoints for hello + TLS session diagnostics
├── client/HybridTlsClient.java       # Probe client with TLS 1.3, mTLS, and JSON output support
└── tools/PrintDefaultNamedGroups.java # Prints the effective JSSE named group ordering seen by this JVM

src/main/resources/
├── application.yml               # Base app configuration
├── application-tls.yml           # HTTPS/TLSv1.3 profile
└── application-mtls.yml          # Client certificate requirement and truststore profile
```

## JFR recording

JFR can record TLS handshakes via the `jdk.TLSHandshake` event, but it is important to distinguish that from `-Djavax.net.debug=ssl:handshake`:

- `jdk.TLSHandshake` is a **JFR event**
- `ssl:handshake` is a **JSSE debug log**

Use JFR when you want a structured recording of TLS handshake activity. Use `ssl:handshake` when you need to see the negotiated **named group** such as `X25519MLKEM768`.

### 1. Start the server with a JFR recording enabled

```bash
mkdir -p logs

java -XX:StartFlightRecording=name=tls,maxsize=500M,dumponexit=true,filename=logs/hybrid-tls_%p_%t.jfr,settings=profile \
  -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

### 2. Generate TLS traffic

Call the application with the included client or with `curl -k` so the server actually performs a TLS handshake:

```bash
java -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=JFR \
  --named-group X25519MLKEM768 \
  --trust-all
```

### 3. Print only the TLS handshake events

```bash
jfr print --events jdk.TLSHandshake logs/hybrid-tls_<pid>_<timestamp>.jfr
```

The `jdk.TLSHandshake` event gives you structured fields such as:

- `peerHost`
- `peerPort`
- `protocolVersion`
- `cipherSuite`
- `certificateId`

### 4. Or attach JFR later with `jcmd`

If you want to start the server normally and attach JFR only when needed, find the process ID and run:

```bash
jcmd <PID> JFR.start name=tls duration=60s filename=logs/hybrid-tls-on-demand.jfr settings=profile
```

### 5. How to confirm `X25519MLKEM768`

JFR **does not include the TLS named group** in `jdk.TLSHandshake`, so JFR alone cannot prove that `X25519MLKEM768` was negotiated.

To confirm the named group, run the client or server with JSSE handshake debug enabled:

```bash
java -Djavax.net.debug=ssl:handshake \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=Debug \
  --named-group X25519MLKEM768 \
  --trust-all
```

Then look for `X25519MLKEM768` in the debug output.

If the JSSE debug log shows `"client version": "TLSv1.2"` in `ClientHello` or `"server version": "TLSv1.2"` in `ServerHello`, that is still normal for a TLS 1.3 handshake. In TLS 1.3, those fields are legacy compatibility values. To confirm the real negotiated protocol, look for `supported_versions`, `selected version: [TLSv1.3]`, `Negotiated protocol version: TLSv1.3`, or a TLS 1.3-only cipher suite such as `TLS_AES_256_GCM_SHA384`.

In practice, use both together:

- **JFR** for structured evidence that TLS 1.3 handshakes happened and which cipher suite was used
- **`ssl:handshake` debug logs** for the exact named group, including `X25519MLKEM768`

For example:

```bash
java -Djavax.net.debug=ssl:handshake \
  -Djdk.tls.client.protocols=TLSv1.3 \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=JFR \
  --named-group X25519MLKEM768 \
  --trust-all
```
