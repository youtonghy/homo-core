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
