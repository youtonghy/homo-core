# homo-core 内核功能变更记录

本文档用于记录本内核相对上游 mihomo 增加或增强的功能。后续每次加入自定义功能、兼容性增强或行为变更时，都应在同一个提交中同步更新本文档，便于回溯功能来源、配置方式和验证范围。

## 2026-05-26 OpenVPN 兼容性增强

### 背景

原 OpenVPN 出站实现主要覆盖 `tls-crypt`、`SHA256`、无压缩的基础配置。实际 `.ovpn` 配置中还常见 `tls-auth` / `auth-tls`、`key-direction`、`SHA1`、`compress` / `comp-lzo no`、以及通过 TLS exporter 派生数据通道密钥的服务端协商方式。

### 新增能力

- `openvpn` 出站支持 `tls-auth`，并兼容 `auth-tls` 别名。
- 支持 `key-direction: 0` / `key-direction: 1`，用于 `tls-auth` 静态密钥方向选择。
- `auth` 支持 `SHA1` 和 `SHA256`，默认值调整为 OpenVPN 常用的 `SHA1`。
- 支持基础压缩 framing：`compress` / `compress stub`、`stub-v2`、`comp-lzo no`。
- 支持服务端通过 PUSH 回复协商 `key-derivation tls-ekm` / `protocol-flags tls-ekm` 时使用 TLS exporter 派生数据通道密钥。
- 改进 PUSH 控制消息处理，支持忽略 `INFO` / `INFO_PRE` / `AUTH_PENDING`，并对 `AUTH_FAILED` 返回明确错误。
- 控制通道抽象为通用 wrapper，使 `tls-crypt` 与 `tls-auth` 可以共用控制包编码/解码流程。
- `docs/config.yaml` 增加 `tls-auth`、`auth-tls`、`key-direction`、`compress` 配置示例说明。

### 配置示例

```yaml
proxies:
  - name: openvpn-example
    type: openvpn
    server: vpn.example.com
    port: 1194
    proto: udp
    cipher: AES-128-GCM
    auth: SHA1
    ca: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    username: user
    password: pass
    tls-auth: |
      -----BEGIN OpenVPN Static key V1-----
      ...
      -----END OpenVPN Static key V1-----
    key-direction: 1
    compress: true
```

### 验证范围

- 新增和扩展 OpenVPN 配置、控制通道、数据通道、压缩 framing、key-method、PUSH 解析相关单元测试。
- 更新 `docs/config.yaml` 的 OpenVPN 配置注释，确保用户能从 `.ovpn` 常见字段映射到 mihomo 配置。

## 2026-05-26 `PROCESS-NAME` 支持 macOS App Bundle 路径前缀匹配

### 背景

macOS 的 `.app` 应用包内可能包含多个实际发起网络连接的二进制文件，例如主程序、helper、framework 内部 helper 等。传统 `PROCESS-NAME` 只按进程 basename 精确匹配时，需要为同一个应用包维护多条规则。

Surge Mac 6.0 起扩展了 `PROCESS-NAME` 语义：当规则 payload 是绝对路径时匹配进程完整路径；当 payload 以 `/` 结尾时进行路径前缀匹配。该能力可用一条规则覆盖某个 `.app` 应用包内所有二进制。

### 新增能力

- `PROCESS-NAME,<name>` 保持原有 basename 精确匹配。
- `PROCESS-NAME,/absolute/path/to/executable` 匹配 `metadata.ProcessPath` 的完整路径。
- `PROCESS-NAME,/Applications/AppName.app/` 对 `metadata.ProcessPath` 执行大小写不敏感的前缀匹配。
- `PROCESS-PATH`、`PROCESS-NAME-REGEX`、`PROCESS-NAME-WILDCARD` 等其他规则类型保持原语义不变。

### 配置示例

```yaml
rules:
  - PROCESS-NAME,/Applications/ChatGPT.app/,DIRECT
```

该规则可匹配：

```text
/Applications/ChatGPT.app/Contents/MacOS/ChatGPT
/Applications/ChatGPT.app/Contents/Frameworks/ChatGPT Helper.app/Contents/MacOS/ChatGPT Helper
```

但不会匹配相邻路径：

```text
/Applications/ChatGPT.app.evil/Contents/MacOS/Other
```

### 验证范围

- 新增 `rules/common/process_test.go`，覆盖 basename 匹配、绝对路径匹配、App Bundle 前缀匹配、相邻路径不误匹配。
- 同时覆盖 `PROCESS-PATH` 精确匹配行为不变，避免把前缀语义扩散到其他规则类型。
