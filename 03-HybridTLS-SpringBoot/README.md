# Java 27 Hybrid TLS Spring Boot 4.1 Demo

Simple Spring Boot 4.1.0 REST API for demonstrating **Hybrid TLS over TLS 1.3** on **Java 27**.

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

### 4. Force the hybrid group from `curl` (when supported)

If your `curl` uses a TLS backend that understands hybrid groups such as `X25519MLKEM768`,
you can restrict the offered group list to that single value:

```bash
curl -vk \
  --tlsv1.3 \
  --tls-max 1.3 \
  --curves X25519MLKEM768 \
  "https://localhost:8443/api/hello?name=curl"
```

The important part is `--curves X25519MLKEM768`: that makes the client offer only the hybrid
group. If the server was started with `APP_TLS_NAMED_GROUPS="X25519MLKEM768"` and the request
succeeds, the handshake negotiated the hybrid group.

Notes:

- `--tlsv1.3 --tls-max 1.3` forces TLS 1.3 instead of “TLS 1.3 or greater”
- not every `curl` build can do this; support depends on the linked TLS library
- if `curl` rejects the group name or the handshake fails immediately, use the included
  `HybridTlsClient` for deterministic verification

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
├── client/HybridTlsClient.java       # Probe client with TLS 1.3, mTLS, JSON output, and custom TLS JFR audit event
├── jfr/TlsHandshakeAuditEvent.java   # Custom event shared by client and server TLS audit emitters
├── jfr/ServerTlsHandshakeAuditFilter.java # Emits server-side custom TLS audit events for secure inbound requests
└── tools/PrintDefaultNamedGroups.java # Prints the effective JSSE named group ordering seen by this JVM

src/main/resources/
├── application.yml               # Base app configuration
├── application-tls.yml           # HTTPS/TLSv1.3 profile
└── application-mtls.yml          # Client certificate requirement and truststore profile
```

## JFR recording

This demo supports both:

- `jdk.TLSHandshake` is a **JFR event**
- `dev.logicojp.example.pqchybridtls.TlsHandshakeAudit` is a **custom JFR event** emitted by both client and server paths

The custom event adds fields that `jdk.TLSHandshake` does not expose, especially `negotiatedNamedGroup`.

Important: JFR recordings are **per JVM process**.  
If you want evidence from both sides, start recording on both the server JVM and the client JVM.

In this project, `dev.logicojp.example.pqchybridtls.TlsHandshakeAudit` is emitted by:

- `HybridTlsClient` (client side)
- `ServerTlsHandshakeAuditFilter` (server side, secure inbound requests)

### 1. Start the server with a JFR recording enabled

If you changed source code, run `mvn package` first so `-jar` uses the latest classes.

```bash
mkdir -p logs

java --add-opens java.base/sun.security.ssl=ALL-UNNAMED \
  -XX:StartFlightRecording=name=tls,maxsize=500M,dumponexit=true,filename=logs/hybrid-tls_%p_%t.jfr,settings=profile \
  -jar target/pqchybridtls-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=tls
```

### 2. Run the client with its own JFR recording (custom event emission)

```bash
java --add-opens java.base/sun.security.ssl=ALL-UNNAMED \
  -XX:StartFlightRecording=name=tls-client,dumponexit=true,filename=logs/hybrid-tls-client_%p_%t.jfr,settings=profile \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=JFR \
  --named-group X25519MLKEM768 \
  --trust-all
```

The `--add-opens` option enables negotiated named group capture from JSSE internals.
Without it, the custom event still emits but `negotiatedNamedGroup` may show `unavailable`.
The same applies to the **server JVM** if you want server-side custom events to resolve the
negotiated group for generic clients such as `curl`.

### 3. Print built-in TLS handshake events (server recording)

```bash
jfr print --events jdk.TLSHandshake logs/hybrid-tls_<pid>_<timestamp>.jfr
```

This command prints only the built-in event. It does **not** include
`dev.logicojp.example.pqchybridtls.TlsHandshakeAudit`.

### 4. Print custom audit events from the server recording

```bash
jfr print --stack-depth 64 \
  --events dev.logicojp.example.pqchybridtls.TlsHandshakeAudit \
  logs/hybrid-tls_<pid>_<timestamp>.jfr
```

### 5. Print custom named-group audit events (client recording)

```bash
jfr print --stack-depth 64 \
  --events dev.logicojp.example.pqchybridtls.TlsHandshakeAudit \
  logs/hybrid-tls-client_<pid>_<timestamp>.jfr
```

The custom event includes:

- `targetUrl`
- `tlsVersion`
- `cipherSuite`
- `negotiatedNamedGroup`
- `configuredNamedGroups`
- `certSigAlgorithm`
- `peerSubject`

The custom event also records the Java stack trace at the point where the event is committed.
For this project, that means the stack will lead back to the client emitter
(`HybridTlsClient`) or the server emitter (`ServerTlsHandshakeAuditFilter`), not to a native
OpenSSL stack.

For server-side custom events:

- `tlsVersion` falls back to `SSLSession.getProtocol()` if the servlet container does not expose a TLS protocol attribute
- `configuredNamedGroups` shows the explicit `jdk.tls.namedGroups` override when present, otherwise the effective JSSE default named group list from `SSLContext.getDefault().getDefaultSSLParameters().getNamedGroups()`

For server-side custom events, `negotiatedNamedGroup` resolution order is:

1. Server-side `SSLEngine` capture during the TLS handshake, stored on the `SSLSession`
2. Reflection via `jakarta.servlet.request.ssl_session_mgr` + `SSLSession` internals
3. Client-provided `X-PQC-Negotiated-Named-Group` header (sent by `HybridTlsClient`)

So when traffic is generated by `HybridTlsClient`, server-side events can record the negotiated group
even if Tomcat/JDK internals do not expose it directly at servlet layer.

That server-side `SSLEngine` capture also works for generic clients. For example:

```bash
curl -sk "https://localhost:8443/api/hello?name=JFR"
```

With the server started using `--add-opens`, the custom JFR event can then show a real value such as
`x25519` for `curl`, even though no client-side helper header is present.

Important when testing protocol versions with `curl`:

- `curl --tlsv1.2` means **TLS 1.2 or greater**, not “TLS 1.2 only”
- this demo's `tls` profile enables only `TLSv1.3`, so `curl --tlsv1.2` can still negotiate TLS 1.3 and JFR should correctly record `TLSv1.3`
- if you want to force TLS 1.2 from `curl`, use `--tlsv1.2 --tls-max 1.2`; with the current server configuration that handshake should fail instead of downgrading

### 6. Or attach JFR later with `jcmd`

If you want to start the server normally and attach JFR only when needed, find the process ID and run:

```bash
jcmd <PID> JFR.start name=tls duration=60s filename=logs/hybrid-tls-on-demand.jfr settings=profile
```

### 7. Fallback: JSSE debug log

If you need low-level handshake troubleshooting, run the client or server with JSSE handshake debug enabled:

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

In practice:

- use **`dev.logicojp.example.pqchybridtls.TlsHandshakeAudit`** for structured named-group evidence
- use **`ssl:handshake` debug logs** when you need deeper troubleshooting detail

Troubleshooting example:

```bash
java -Djavax.net.debug=ssl:handshake \
  -Djdk.tls.client.protocols=TLSv1.3 \
  -cp target/classes \
  dev.logicojp.example.pqchybridtls.client.HybridTlsClient \
  --url https://localhost:8443/api/hello?name=JFR \
  --named-group X25519MLKEM768 \
  --trust-all
```
