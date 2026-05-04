# Legendary-WhiteHat-Scanner
> 传说级白帽专业漏洞扫描器 | 2026 国际标准开源版

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.6+-blue.svg" alt="Python">
</p>

---

## 📖 项目简介
**Legendary-WhiteHat-Scanner** 是一款面向白帽安全工程师的自动化漏洞检测工具，严格遵循 OWASP Top 10、等保2.0 及 ISO27001 安全框架标准，提供 Web/API 全场景漏洞扫描、PoC 验证与标准化报告生成能力。

---

## ✨ 核心特性
- 🎯 高精准检测：内置 100+ 漏洞检测规则，覆盖 SQL 注入、XSS、文件上传等高危漏洞
- 🔍 PoC 一键验证：自动生成可复现漏洞证明
- 📊 生成专业报告：支持 HTML 报告，可直接提交 SRC / 等保测评
- 🚀 轻量跨平台：Windows / Linux / macOS 通用
- 🛡️ 安全合规：MIT 开源协议，可自由使用与修改

---

## 🚀 快速开始
### 1. 安装依赖
```bash
pip install requests
2. 运行扫描器
python scanner.py

📌 使用流程
配置目标：输入待扫描的 URL 或 IP 地址
选择模块：根据需求选择全量扫描或指定漏洞类型扫描
执行扫描：等待工具自动完成检测与验证
查看报告：扫描完成后，报告将自动保存至 ./report/ 目录
Legendary-WhiteHat-Scanner/
├── scanner.py          # 主程序入口
├── modules/            # 漏洞检测模块
├── poc/                # PoC 验证脚本
├── report/             # 扫描报告目录
└── README.md           # 项目说明文档


⚠️ 免责声明
本工具仅用于合法授权的安全测试与合规评估。
使用方需自行承担因非法使用导致的所有法律责任。

📄 开源协议
本项目采用 MIT License 开源协议。
你可以自由使用、修改、分发本项目，但需保留原作者版权声明。




