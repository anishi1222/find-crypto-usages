# Java 27 (or later) default JSSE named groups

This directory contains a minimal helper for printing the named groups that the
current Java runtime exposes through JSSE default SSL parameters.

Use it with **JDK 27 or later**. Java 27 or later includes the TLS 1.3 hybrid named group
`X25519MLKEM768`, and it should appear first in the default order when no
`jdk.tls.namedGroups` override is set.

The source intentionally uses Java's simplified launch entry point:
`void main()`.

## Requirements

- JDK 27 or later
- No Maven or Gradle required

Check the runtime:

```bash
java -version
```

## Run

From the repository root:

```bash
cd 01-NamedGroups
java PrintDefaultNamedGroups.java
```

Expected shape:

```text
java.runtime.version = 27-ea+...
X25519MLKEM768
x25519
secp256r1
...
```

The exact version string and full list can vary by JDK build, but on JDK 27 the
important check is that `X25519MLKEM768` is present and is the first default
named group.

## Run with an explicit override

To show how the JVM property changes the effective list, run:

```bash
java \
  -Djdk.tls.namedGroups=X25519MLKEM768,x25519,secp256r1 \
  PrintDefaultNamedGroups.java
```

This is useful before running the TLS demos because it confirms which named
groups the same Java process will offer to JSSE.
