---
name: chain-bin-audit
description: Use when auditing a blockchain node upgrade package for security — verifying archive hash, scanning binaries with VirusTotal, detecting embedded on-chain addresses, before deploying the upgrade. Triggers on keywords like node upgrade, binary audit, chain upgrade package, upgrade security check.
---

# Chain Binary Audit

自动化安全审计区块链节点升级包。验证压缩包完整性，扫描二进制恶意软件，检测嵌入的链上地址。

**核心原则：** 宁可多报不漏报——所有不确定的发现都保留给人工审查。

## 输入

开始前从用户收集：

| 参数 | 必填 | 说明 |
|------|------|------|
| `archive_path` | 是 | 压缩包路径（.tar.gz 或 .zip） |
| `hash` | 是 | 期望的 SHA256 哈希值 |
| `chains` | 否 | 目标链列表（如 "ETH, BTC, Solana"），默认：ETH, BTC, Solana, Tron, Cosmos |

## 前置检查

开始前验证：

1. `VT_API_KEY` 环境变量：`echo "${VT_API_KEY:+set}"` — 为空则跳过 VT 扫描（不阻断流程）
2. `python3`、`file`、`strings`、`sha256sum`、`curl` 可用
3. 压缩包文件存在

## 审计流程

按顺序执行步骤 1–6。**任何步骤失败都不终止流程**——记录问题后继续。

### 步骤 1：Hash 校验

```bash
ACTUAL_HASH=$(sha256sum "<archive_path>" | cut -d' ' -f1)
```

与用户提供的 `hash` 进行比对（不区分大小写）。

- **一致：** 记录 ✅ PASS
- **不一致：** 记录 ⚠️ MISMATCH，包含期望值和实际值。标记为**高优先级风险**但**不终止审计**。

### 步骤 2：解压并识别二进制文件

1. 创建隔离的解压目录：
```bash
EXTRACT_DIR=$(mktemp -d)
```

2. 按扩展名解压：
```bash
# .tar.gz / .tgz:
tar xzf "<archive_path>" -C "$EXTRACT_DIR" --no-same-owner

# .zip:
unzip -o "<archive_path>" -d "$EXTRACT_DIR"
```

3. **安全措施：** 解压后检查并移除指向外部的符号链接：
```bash
find "$EXTRACT_DIR" -type l | while read -r link; do
    target=$(readlink -f "$link" 2>/dev/null || true)
    case "$target" in
        "$EXTRACT_DIR"*) ;;
        *) rm "$link" && echo "已移除符号链接: $link -> $target" ;;
    esac
done
```

4. 识别所有可执行二进制文件：
```bash
find "$EXTRACT_DIR" -type f -exec file {} \; | grep -iE "ELF|executable|shared object|Mach-O" | cut -d: -f1
```

5. 记录文件清单：文件名、类型（`file` 输出）、大小。

如未找到二进制文件，记录"压缩包内未发现可执行二进制文件"并跳过步骤 3–5。

### 步骤 3：VirusTotal 扫描

**跳过条件：** `VT_API_KEY` 未设置时，记录"VT 扫描跳过：未配置 API Key"并进入步骤 4。

对步骤 2 识别的**每个**二进制文件执行：

```bash
bash ~/.claude/skills/chain-bin-audit/scripts/vt_scan.sh "<binary_path>"
```

脚本输出 JSON，解析并记录：
- `status`："clean" / "detected" / "timeout" / "error" / "skipped"
- `detection_rate`：如 "0/72"
- `engines`：标记的引擎（仅 detected 时）
- `vt_link`：VT 分析页面链接
- `error_msg`：跳过/错误原因

**重要——限流：** 免费 VT API 仅允许 4 次请求/分钟。
- 逐个处理文件，绝不并行
- 脚本内置 15 秒间隔
- 如二进制文件较多（>10），提前告知用户需要较长时间

### 步骤 4：链上地址检测

**两阶段流程：AI 生成提取规则 → AI 审核结果**

**阶段 1——生成并执行提取：**

根据用户的 `chains` 参数（或默认值），可以：
- 直接使用参考脚本：
```bash
python3 -I ~/.claude/skills/chain-bin-audit/scripts/detect_addresses.py \
    --chains "<chain_list>" <binary_1> <binary_2> ...
```
- 或者：如果用户的目标链不在默认集合中，**动态生成**自定义 Python 提取脚本。自定义脚本必须：
  - 接受二进制文件路径作为参数
  - 使用 `strings` 提取可打印内容（绝不执行二进制文件）
  - 应用目标链的正则模式
  - 输出 JSON 数组 `{address, chain_hint, file, offset_hex, context}`

**阶段 2——AI 分类：**

逐一审查阶段 1 输出的每个候选地址，分为三类：

| 分类 | 标准 | 报告处理 |
|------|------|----------|
| **确认** | Checksum 有效，格式正确，看起来是真实地址 | 加入"确认地址"表，标记"待人工确认是否内部地址" |
| **排除** | 明确非地址——内存指针（0x00007fff...）、编译器常量、常见 hex 模式、哈希片段 | 不收录到报告 |
| **存疑** | 格式匹配但无法验证——无法做 checksum 校验、上下文不明确 | 加入"存疑地址"表，注明存疑原因 |

**分类指南：**
- ETH：验证 0x 前缀 + 40 个 hex 字符。混合大小写时验证 EIP-55 checksum。全小写或全大写有效但标为存疑。
- BTC legacy：以 1 或 3 开头，Base58Check 编码，长度 25-34。
- BTC bech32：以 bc1 开头，仅小写。
- Solana：Base58 编码，32-44 字符。**误报率极高**——需要上下文看起来像地址（config、wallet、account 等关键词）。
- Tron：以 T 开头，34 字符 Base58。
- Cosmos：以 cosmos1 开头，bech32 编码。

**偏向存疑而非排除**——有疑问时保留给人工审查。

### 步骤 5：投毒检测（预留）

报告中记录："⏳ 预留：待投毒检测 skill 实现后接入"

未来投毒检测 sub-skill 可用时在此调用，输入为二进制文件路径列表。

### 步骤 6：生成 Markdown 报告

在**当前工作目录**创建报告文件，命名：`audit-report-<压缩包名>-<YYYYMMDD-HHMMSS>.md`

使用以下模板（填入实际值）：

```
# 区块链节点升级包安全审计报告

**审计时间：** <timestamp>
**压缩包：** <文件名>
**目标链：** <链列表>

---

## 1. Hash 校验

| 项目 | 值 |
|------|-----|
| 期望 Hash | <expected> |
| 实际 Hash | <actual> |
| 结果 | ✅ PASS / ⚠️ MISMATCH |

---

## 2. 二进制文件清单

| # | 文件名 | 类型 | 大小 |
|---|--------|------|------|
| 1 | <name> | <file type> | <size> |

---

## 3. VirusTotal 扫描结果

### 3.1 <文件名>
- **检出率：** <rate>
- **状态：** ✅ 未检出威胁 / ⚠️ 检出威胁
- **标记引擎：** <引擎列表，仅检出时>
- **VT 链接：** <url>

（VT 跳过时显示："VT 扫描跳过：未配置 API Key"）

---

## 4. 链上地址检测

### 确认地址
| # | 地址 | 链 | 所在文件 | 待人工确认是否内部地址 |
|---|------|----|----------|----------------------|
（行数据，或"未检测到确认的链上地址"）

### 存疑地址（待人工确认）
| # | 候选值 | 可能链 | 所在文件 | 存疑原因 |
|---|--------|--------|----------|----------|
（行数据，或"无存疑地址"）

---

## 5. 投毒检测

> ⏳ 预留：待投毒检测 skill 实现后接入

---

## 6. 总结

| 检查项 | 结果 |
|--------|------|
| Hash 校验 | ✅ PASS / ⚠️ MISMATCH |
| VT 扫描 | ✅ 全部通过 / ⚠️ N 个文件检出威胁 / ⏭️ 跳过 |
| 地址检测 | ✅ 未检出 / ⚠️ 发现 N 个地址待人工确认 |
| 投毒检测 | ⏳ 未执行 |
```

报告生成后，告知用户报告路径，并在终端打印**总结**表。

### 清理

报告生成后：
```bash
rm -rf "$EXTRACT_DIR"
```

## 常见错误

| 错误 | 纠正 |
|------|------|
| 执行了压缩包中的二进制文件 | 绝不执行——仅使用 `file`、`strings`，只读分析 |
| 输出中出现 VT_API_KEY | 仅从环境变量读取，绝不 echo 或记录 |
| Hash 不匹配时终止审计 | 记录后继续——所有步骤无论如何都要执行 |
| 并行调用 VT API | 始终串行，间隔 ≥15 秒——免费版限制 |
| 信任 Solana 正则匹配 | Solana base58 误报率极高——大部分应分类为存疑 |
| 忘记清理临时目录 | 报告生成后始终 `rm -rf "$EXTRACT_DIR"` |
