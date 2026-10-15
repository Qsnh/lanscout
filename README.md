# LanScout

LanScout 是一个局域网设备与 IP 扫描工具，支持 macOS 和 Windows。它会列出当前局域网里有哪些设备、各自用的是哪个 IP，并尽量认出每台设备是什么（路由器、电脑、手机、打印机、摄像头、NAS、电视、智能家居……），方便你分配 IP 地址、避免冲突。

界面用 [MyGo](https://mygo.egoist.dev/docs) 的原生 UI（`package ui`）编写，由 MyGo 直接在 GPU 上绘制：macOS 用 Metal，Windows 用 Direct3D 11。没有 WebView，也没有前端。整个程序是一个纯 Go、不依赖 cgo 的可执行文件，运行时不需要管理员权限。

![设备列表](docs/table.png)
![IP 分布图](docs/map.png)

## 功能

- **一键扫描**：自动选中默认网卡和所在网段（例如 `192.168.1.0/24`），一个 /24 网段一般 10 秒内扫完，结果边扫边显示。也可以手动指定网段，最大支持 /20（4096 个地址）。
- **识别设备**：
  - 厂商：根据 MAC 前缀查内置的 IEEE 厂商库（5.8 万条），常见品牌显示中文名，例如「华为 Huawei」「小米 Xiaomi」「普联 TP-Link」
  - 名称：依次通过 mDNS（苹果设备、Linux）、NetBIOS（Windows 电脑、Samba）、反向 DNS（路由器的 DHCP 记录）、UPnP/SSDP（电视、路由器、NAS）获取，还会读取设备网页的标题
  - 类型和系统：综合型号、名称、开放端口（打印 9100/631、iPhone 62078、远程桌面 3389、RTSP 554……）和厂商来推断
  - 标出网关、本机，以及使用随机 MAC（「私有 Wi-Fi 地址」）的手机
- **设备列表**：每一列都可以排序；支持按 IP、名称、厂商、MAC、端口搜索；右键可复制 IP/MAC，或在浏览器中打开设备的管理页面。
- **IP 分布图**：网段里每个地址一个格子，在线、网关、本机、近期使用、空闲用不同颜色区分。点空闲格子就会复制这个 IP，旁边还列出最长的几段连续空闲地址，可直接填到路由器的 DHCP 地址池或静态分配表里。
- **离线设备记录**：每次扫描的结果都会保存下来。最近 30 天出现过、但这次没有响应的设备，会以「近期使用」显示，提醒你别把它的 IP 分给别人。
- **导出 CSV**：网段里每个地址的使用情况（在线 / 曾使用 / 空闲），可用 Excel 直接打开。
- 跟随系统的浅色/深色模式，快捷键 ⌘R / Ctrl+R 重新扫描。

## 工作原理

1. **扫一遍网段**：对每个地址同时发 ICMP ping，并尝试连接几个常见 TCP 端口。对方无论接受还是拒绝连接，都说明这个 IP 上有设备。ping 用的是不需要管理员权限的方式：macOS 用无特权 ICMP 套接字，Windows 用 `IcmpSendEcho`。
2. **读 ARP 表**：上一步发出的探测会让系统对每个地址做 ARP 解析。扫描过程中会反复读取系统 ARP 表（macOS 用 `arp -an`，Windows 用 `GetIpNetTable`），这样连不回 ping、不开端口的手机也能发现，同时拿到每台设备的 MAC 地址。
3. **识别设备**：对每台在线设备扫描 26 个常见端口，查询反向 DNS、NetBIOS 和 mDNS，读取 UPnP 描述和网页标题，再综合判断设备类型。

## 使用

### 下载安装

到 [Releases](https://github.com/Qsnh/lanscout/releases) 下载对应系统的文件：

| 系统 | 安装包 | 免安装版 |
| --- | --- | --- |
| macOS（Apple 芯片和 Intel） | `LanScout-<版本>-macos-universal.dmg`，打开后把 LanScout 拖进「应用程序」 | `LanScout-<版本>-macos-universal.zip`，解压即可运行 |
| Windows x64 | `LanScout-<版本>-windows-amd64-setup.exe`，装在当前用户下，不需要管理员权限 | `LanScout-<版本>-windows-amd64.zip`，解压后运行 `LanScout.exe` |
| Windows ARM64 | `LanScout-<版本>-windows-arm64-setup.exe` | `LanScout-<版本>-windows-arm64.zip` |

应用暂未做代码签名：macOS 第一次打开时如果提示无法打开或无法验证，请到「系统设置 › 隐私与安全性」，在页面下方点「仍要打开」；Windows 如果提示「Windows 已保护你的电脑」，点「更多信息」，再点「仍要运行」。

### 直接运行

```sh
go tool mygo dev      # 开发模式运行，改代码后自动重启
```

macOS 第一次扫描时，系统会询问是否允许 LanScout「查找本地网络上的设备」，请点「允许」。如果之前点了拒绝，可以到「系统设置 › 隐私与安全性 › 本地网络」里打开。

Windows 第一次扫描时，Windows 防火墙可能会询问是否允许 LanScout 访问网络（UPnP 发现需要接收设备的回复），选「专用网络」并允许即可。即使不允许，扫描也照样能做，只是电视、路由器这类设备可能认不出名字。

### 命令行版

不开窗口、直接在终端里扫描，适合排查问题或写脚本：

```sh
go run ./cmd/lanscan                     # 扫描默认网卡所在的网段
go run ./cmd/lanscan -net 10.0.0.0/22    # 扫描指定网段
go run ./cmd/lanscan -if en0             # 指定网卡
```

不下载源码也能直接运行：

```sh
go run github.com/Qsnh/lanscout/cmd/lanscan@latest
```

### 打包

```sh
go tool mygo build -platform darwin/universal,windows/amd64,windows/arm64
```

打包结果在 `build/` 目录下：

| 平台 | 产物 |
| --- | --- |
| macOS | `LanScout.app`，以及安装用的 `LanScout 0.1.0.dmg` |
| Windows | `LanScout.exe`（图形界面程序，不会弹出控制台窗口）；装了 [NSIS](https://nsis.sourceforge.io) 的话还会生成安装包 `LanScout Setup 0.1.0 amd64.exe` |

MyGo 不需要 cgo，所以在 Mac 上就能直接编出 Windows 版本。要正式分发的话，需要先签名，参见 [MyGo 的分发文档](https://mygo.egoist.dev/docs/distribution)。

### 发布新版本

推送 `v` 开头的版本标签，GitHub Actions（[`.github/workflows/release.yml`](.github/workflows/release.yml)）就会构建上面「下载安装」里的所有文件，全部成功后创建 GitHub Release，并附上 `SHA256SUMS.txt`：

```sh
git tag v0.2.0
git push origin v0.2.0
```

- 版本号以标签为准，构建时写进 `mygo.json`，不用先改文件。仓库里 `mygo.json` 的版本号只影响本地打包。
- 标签带后缀（如 `v0.2.0-beta.1`）会发布成预发布版本。
- macOS 版在 macOS 机器上构建（制作 dmg 需要 macOS），构建前先跑一遍单元测试；Windows 版在 Ubuntu 上交叉编译，用 NSIS 生成安装程序。
- 如果先在 GitHub 网页上手动创建了 Release（同时创建标签），构建好的文件会传到这个 Release 里，不会改动你写的说明。
- 推送到 main 的提交改了打包相关的文件（这个 workflow、`mygo.json`、`go.mod`、`go.sum`、`resources/`）时，也会试构建一次，但不发布，产物在 Actions 运行页面的 Artifacts 里。也可以在 Actions 页面手动运行（Run workflow）。

## 开发

需要 Go 1.27 或更高版本（`go.mod` 里已经写好，`GOTOOLCHAIN=auto` 会自动下载）。

```sh
go test ./...          # 单元测试，包括不开窗口的 UI 测试
go tool mygo vet .     # 检查 MyGo 原生 UI 的用法
```

`LANSCOUT_SHOTS=docs go test .` 会把 UI 测试渲染出来的画面保存成 PNG，也就是上面那两张截图。

### 代码结构

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

## 局限

- 只能扫描同一个二层网段内的设备，路由器另一侧的网段拿不到 MAC 和厂商。
- 「空闲」只表示这个地址这次没有响应。关机、休眠或者禁 ping 的设备不会显示出来，所以分配 IP 前，最好再对照一下路由器的 DHCP 列表。
- 开了「私有 Wi-Fi 地址」的手机用的是随机 MAC，查不到厂商；如果要在路由器里给它绑定固定 IP，需要先在手机上关闭这个网络的私有地址。
- 暂不支持 IPv6。
