# TLS client/server demo

このディレクトリは、Spring などのフレームワークを使わずに JDK API だけで
HTTPS/TLS 1.3 の server/client を動かす最小デモです。

- `PqcHttpsServer.java`: `HttpsServer` で `https://localhost:8443/` を起動します。
- `PqcHttpsClient.java`: `HttpClient` で server に接続し、`truststore.p12` で server 証明書を検証します。

## 事前に必要なもの

- JDK 27以上
- `keytool`（JDK に同梱）
- `curl`（疎通確認用、任意）
- `rg`（TLS handshake debug log の検索用、任意）

JDK 27 を推奨する理由は、Java 27 の JSSE が TLS 1.3 の hybrid named group
`X25519MLKEM768` を扱えるためです。このデモの証明書は通常の RSA 証明書で問題ありません。
Hybrid TLS の PQC 部分は証明書ではなく TLS 1.3 の key exchange named group です。

確認:

```bash
cd 02-TLS_client_server
java -version
keytool -help >/dev/null
```

## 準備するファイル

実行前に、同じディレクトリに次の 2 つが必要です。

| ファイル | 用途 | 読み込む側 | デフォルトパス |
|---|---|---|---|
| `keystore.p12` | server の秘密鍵と証明書 | `PqcHttpsServer.java` | 変更可: `KEYSTORE_PATH` |
| `truststore.p12` | client が信頼する server 証明書 | `PqcHttpsClient.java` | 固定: `truststore.p12` |

デフォルトパスワードはどちらも `changeit` です。

## 既存の `keystore.p12` から `truststore.p12` を作る

このディレクトリに `keystore.p12` が既にある場合は、server 証明書を export して
client 用 truststore に import します。

まず alias を確認します。現在のサンプル keystore では `mykey` です。

```bash
cd 02-TLS_client_server

keytool -list \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit
```

証明書を export します。

```bash
keytool -exportcert \
  -alias mykey \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit \
  -rfc \
  -file server-cert.pem
```

client 用 truststore を作成します。

```bash
keytool -importcert \
  -alias tls-demo-server \
  -file server-cert.pem \
  -storetype PKCS12 \
  -keystore truststore.p12 \
  -storepass changeit \
  -noprompt
```

確認:

```bash
keytool -list \
  -storetype PKCS12 \
  -keystore truststore.p12 \
  -storepass changeit
```

## `keystore.p12` も含めて作り直す

手元で完全に作り直す場合は、次の手順で server keystore と client truststore を作成します。
既存ファイルを上書きしたくない場合は、先に別名で退避してください。

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

## 実行方法

Terminal A で server を起動します。

```bash
cd 02-TLS_client_server
java PqcHttpsServer.java
```

期待される出力:

```text
Server started on https://localhost:8443
Using keystore: ...
```

別の keystore を使う場合は環境変数で指定します。

```bash
KEYSTORE_PATH=/path/to/keystore.p12 \
KEYSTORE_PASSWORD=changeit \
java PqcHttpsServer.java
```

Terminal B で client を実行します。

```bash
cd 02-TLS_client_server
java PqcHttpsClient.java
```

期待される出力:

```text
200
Hello from Java TLSv1.3
```

`curl` で確認する場合:

```bash
curl --cacert server-cert.pem https://localhost:8443/
```

証明書検証を省略した疎通確認だけなら:

```bash
curl -k https://localhost:8443/
```

## Hybrid named group を明示して動かす

JDK 27 のデフォルトでは `X25519MLKEM768` が優先されますが、デモで明示したい場合は
server と client の両方に `jdk.tls.namedGroups` を指定します。

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

handshake の詳細を見たい場合:

```bash
java \
  -Djdk.tls.namedGroups=X25519MLKEM768 \
  -Djavax.net.debug=ssl:handshake \
  PqcHttpsClient.java 2>&1 | tee client-handshake.log

rg -i 'x25519mlkem768|key_share|named group|named_group' client-handshake.log
```

## トラブルシューティング

### `truststore.p12 (No such file or directory)`

client が `truststore.p12` を見つけられていません。
「既存の `keystore.p12` から `truststore.p12` を作る」の手順を実行してください。

### `PKIX path building failed`

client の truststore に server 証明書が入っていない、または server が別の keystore を使っています。
server 起動時に表示される `Using keystore: ...` を確認し、その keystore から証明書を export/import してください。

### `Address already in use`

port `8443` が既に使われています。既存の server プロセスを停止してから再実行してください。

### `Named group X25519MLKEM768 is not supported`

JDK が `X25519MLKEM768` に対応していません。JDK 27 で実行してください。
