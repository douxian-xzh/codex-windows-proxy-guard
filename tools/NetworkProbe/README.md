# NetworkProbe

Windows x64 的最小原生套接字探针，用于后续透明转发正负对照。程序不读取 Windows 系统代理、WinHTTP、环境代理变量或管理器设置。

支持 TCP connect、TLS 验证、UDP 单包、UDP echo；目标必须是字面 IPv4/IPv6 地址，避免探针本身的 DNS 行为污染对照。每次 JSON 输出包含 PID、创建时间、映像路径、目标、模式和结果。TLS 使用系统证书验证并要求显式 SNI。

示例：

```powershell
NetworkProbe.exe --mode tcp --ip 203.0.113.20 --port 443
NetworkProbe.exe --mode tls --ip 203.0.113.20 --port 443 --server-name api.example.test
NetworkProbe.exe --mode udp-echo --ip 127.0.0.1 --port 9000 --timeout-ms 5000
```

`tools/NetworkProbe.SelfTest` 复制同一探针到不同 Target / Control 目录，以 IPv4 与 IPv6 loopback TCP、UDP echo 验证两份程序。该 loopback 自测不启动 ProxiFyre，也不证明透明代理或非目标路由结果。
