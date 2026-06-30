# TLS client/server demo

[Japanese README](README_ja.md)

This directory contains a minimal HTTPS/TLS 1.3 server/client demo built only with
JDK APIs, without Spring or other application frameworks.

- `PqcHttpsServer.java`: starts an `HttpsServer` at `https://localhost:8443/`.
- `PqcHttpsClient.java`: connects with `HttpClient` and validates the server certificate with `truststore.p12`.

## Prerequisites

- JDK 27 or later
- `keytool` (included with the JDK)
- `curl` (optional, for quick connectivity checks)
- `rg` (optional, for searching TLS handshake debug logs)

JDK 27 is recommended because Java 27 JSSE can use the TLS 1.3 hybrid named group
`X25519MLKEM768`. The certificate used by this demo can remain a conventional RSA
certificate. The PQC part of Hybrid TLS is the TLS 1.3 key exchange named group, not
the certificate.

Check your tools:

```bash
cd 02-TLS_client_server
java -version
keytool -help >/dev/null
```

## Files to prepare

Before running the demo, prepare these two files in this directory.

| File | Purpose | Used by | Default path |
|---|---|---|---|
| `keystore.p12` | Server private key and certificate | `PqcHttpsServer.java` | Override with `KEYSTORE_PATH` |
| `truststore.p12` | Server certificate trusted by the client | `PqcHttpsClient.java` | Fixed: `truststore.p12` |

The default password for both files is `changeit`.

## Create `truststore.p12` from the existing `keystore.p12`

If this directory already has `keystore.p12`, export the server certificate and import
it into a client truststore.

First, check the alias. The current sample keystore uses `mykey`.

```bash
cd 02-TLS_client_server

keytool -list \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit
```

Export the certificate:

```bash
keytool -exportcert \
  -alias mykey \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit \
  -rfc \
  -file server-cert.pem
```

Create the client truststore:

```bash
keytool -importcert \
  -alias tls-demo-server \
  -file server-cert.pem \
  -storetype PKCS12 \
  -keystore truststore.p12 \
  -storepass changeit \
  -noprompt
```

Verify it:

```bash
keytool -list \
  -storetype PKCS12 \
  -keystore truststore.p12 \
  -storepass changeit
```

## Recreate both `keystore.p12` and `truststore.p12`

If you want to recreate everything locally, use the following commands to generate
the server keystore and client truststore. Back up existing files first if you do not
want to overwrite them.

```bash
cd 02-TLS_client_server

# Optional backup
[ -f keystore.p12 ] && cp keystore.p12 keystore.p12.bak
[ -f truststore.p12 ] && cp truststore.p12 truststore.p12.bak

# Regenerate from scratch
rm -f keystore.p12 truststore.p12 server-cert.pem

keytool -genkeypair \
  -alias mykey \
  -keyalg RSA \
  -keysize 2048 \
  -sigalg SHA384withRSA \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit \
  -keypass changeit \
  -validity 365 \
  -dname "CN=localhost, OU=Demo, O=Example, L=Tokyo, ST=Tokyo, C=JP" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"

keytool -exportcert \
  -alias mykey \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit \
  -rfc \
  -file server-cert.pem

keytool -importcert \
  -alias tls-demo-server \
  -file server-cert.pem \
  -storetype PKCS12 \
  -keystore truststore.p12 \
  -storepass changeit \
  -noprompt
```

## Run the demo

Start the server in Terminal A:

```bash
cd 02-TLS_client_server
java PqcHttpsServer.java
```

Expected output:

```text
Server started on https://localhost:8443
Using keystore: ...
```

To use a different keystore, set environment variables:

```bash
KEYSTORE_PATH=/path/to/keystore.p12 \
KEYSTORE_PASSWORD=changeit \
java PqcHttpsServer.java
```

Run the client in Terminal B:

```bash
cd 02-TLS_client_server
java PqcHttpsClient.java
```

Expected output:

```text
200
Hello from Java TLSv1.3
```

To verify with `curl`:

```bash
curl --cacert server-cert.pem https://localhost:8443/
```

For a connectivity-only check that skips certificate validation:

```bash
curl -k https://localhost:8443/
```

## Run with an explicit hybrid named group

On JDK 27, `X25519MLKEM768` is preferred by default. If you want to make the demo
explicit, set `jdk.tls.namedGroups` on both the server and client.

Terminal A:

```bash
cd 02-TLS_client_server
java -Djdk.tls.namedGroups=X25519MLKEM768 PqcHttpsServer.java
```

Terminal B:

```bash
cd 02-TLS_client_server
java -Djdk.tls.namedGroups=X25519MLKEM768 PqcHttpsClient.java
```

To inspect handshake details:

```bash
java \
  -Djdk.tls.namedGroups=X25519MLKEM768 \
  -Djavax.net.debug=ssl:handshake \
  PqcHttpsClient.java 2>&1 | tee client-handshake.log

rg -i 'x25519mlkem768|key_share|named group|named_group' client-handshake.log
```

## Troubleshooting

### `truststore.p12 (No such file or directory)`

The client cannot find `truststore.p12`. Run the steps in
[Create `truststore.p12` from the existing `keystore.p12`](#create-truststorep12-from-the-existing-keystorep12).

### `PKIX path building failed`

The client truststore does not contain the server certificate, or the server is using
a different keystore. Check the `Using keystore: ...` line printed by the server, then
export/import the certificate from that keystore.

### `Address already in use`

Port `8443` is already in use. Stop the existing server process and run the demo again.

### `Named group X25519MLKEM768 is not supported`

The current JDK does not support `X25519MLKEM768`. Run the demo with JDK 27.
