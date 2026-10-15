# LanScout 开发说明

这份文档面向想从源码运行、修改或发布 LanScout 的开发者。只想使用 LanScout 的话，看 [README](../README.md) 就够了。

界面用 [MyGo](https://mygo.egoist.dev/docs) 的原生 UI（`package ui`）编写，由 MyGo 直接在 GPU 上绘制：macOS 用 Metal，Windows 用 Direct3D 11。没有 WebView，也没有前端。整个程序是一个纯 Go、不依赖 cgo 的可执行文件，运行时不需要管理员权限。

## 环境

需要 Go 1.27 或更高版本（`go.mod` 里已经写好，`GOTOOLCHAIN=auto` 会自动下载）。

## 运行

```sh
go tool mygo dev      # 开发模式运行，改代码后自动重启
```

命令行版：

```sh
go run ./cmd/lanscan                     # 扫描默认网卡所在的网段
go run ./cmd/lanscan -net 10.0.0.0/22    # 扫描指定网段
go run ./cmd/lanscan -if en0             # 指定网卡
```

## 测试

```sh
go test ./...          # 单元测试，包括不开窗口的 UI 测试
go tool mygo vet .     # 检查 MyGo 原生 UI 的用法
```

`LANSCOUT_SHOTS=docs go test .` 会把 UI 测试渲染出来的画面保存成 PNG，也就是 README 里的截图。

## 打包

```sh
go tool mygo build -platform darwin/universal,windows/amd64,windows/arm64
```

打包结果在 `build/` 目录下：

| 平台 | 产物 |
| --- | --- |
| macOS | `LanScout.app`，以及安装用的 `LanScout 0.1.0.dmg` |
| Windows | `LanScout.exe`（图形界面程序，不会弹出控制台窗口）；装了 [NSIS](https://nsis.sourceforge.io) 的话还会生成安装包 `LanScout Setup 0.1.0 amd64.exe` |

MyGo 不需要 cgo，所以在 Mac 上就能直接编出 Windows 版本。要正式分发的话，需要先签名，参见 [MyGo 的分发文档](https://mygo.egoist.dev/docs/distribution)。

## 发布新版本

推送 `v` 开头的版本标签，GitHub Actions（[`.github/workflows/release.yml`](../.github/workflows/release.yml)）就会构建 README「下载安装」里列出的所有文件，全部成功后创建 GitHub Release，并附上 `SHA256SUMS.txt`：

```sh
git tag v0.2.0
git push origin v0.2.0
```

- 版本号以标签为准，构建时写进 `mygo.json`，不用先改文件。仓库里 `mygo.json` 的版本号只影响本地打包。
- 标签带后缀（如 `v0.2.0-beta.1`）会发布成预发布版本。
- macOS 版在 macOS 机器上构建（制作 dmg 需要 macOS），构建前先跑一遍单元测试；Windows 版在 Ubuntu 上交叉编译，用 NSIS 生成安装程序。
- 如果先在 GitHub 网页上手动创建了 Release（同时创建标签），构建好的文件会传到这个 Release 里，不会改动你写的说明。
- 推送到 main 的提交改了打包相关的文件（这个 workflow、`mygo.json`、`go.mod`、`go.sum`、`resources/`）时，也会试构建一次，但不发布，产物在 Actions 运行页面的 Artifacts 里。也可以在 Actions 页面手动运行（Run workflow）。

## 工作原理

1. **扫一遍网段**：对每个地址同时发 ICMP ping，并尝试连接几个常见 TCP 端口。对方无论接受还是拒绝连接，都说明这个 IP 上有设备。ping 用的是不需要管理员权限的方式：macOS 用无特权 ICMP 套接字，Windows 用 `IcmpSendEcho`。
2. **读 ARP 表**：上一步发出的探测会让系统对每个地址做 ARP 解析。扫描过程中会反复读取系统 ARP 表（macOS 用 `arp -an`，Windows 用 `GetIpNetTable`），这样连不回 ping、不开端口的手机也能发现，同时拿到每台设备的 MAC 地址。
3. **识别设备**：对每台在线设备扫描 26 个常见端口，查询反向 DNS、NetBIOS 和 mDNS，读取 UPnP 描述和网页标题，再综合判断设备类型。

## 代码结构

```
main.go          创建窗口，启动时自动开始扫描
app.go           应用状态：扫描、历史记录、空闲地址段、CSV 导出
view.go          界面：顶栏、统计卡片、设备表格、详情面板
view_map.go      IP 分布图和空闲地址段
icons.go         图标（Lucide）和各类设备的配色
scan/            扫描引擎，不依赖 UI
  scanner.go     扫描流程：扫网段 → 读 ARP 表 → 识别设备
  netif.go       网卡和网段
  sys_*.go       各平台的 ARP 表和默认网关
  ping_*.go      各平台的 ICMP
  names.go       反向 DNS、NetBIOS、mDNS
  upnp.go        SSDP/UPnP 和网页标题
  classify.go    判断设备类型和系统
  vendor.go      MAC 厂商库（oui.txt.gz，由 gen_oui.go 从 Wireshark 的 manuf 生成）
cmd/lanscan/     命令行版
```
