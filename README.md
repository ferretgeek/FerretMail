<p align="center">
  <img src="docs/images/social-preview.png" alt="自建域名收件箱 — 只收不发的域名邮箱" width="100%">
</p>

# 自建域名收件箱

中文 · [English](README_EN.md)

[![CI](https://github.com/ferretgeek/domain-mail-inbox/actions/workflows/ci.yml/badge.svg)](https://github.com/ferretgeek/domain-mail-inbox/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![零依赖](https://img.shields.io/badge/%E8%BF%90%E8%A1%8C%E4%BE%9D%E8%B5%96-%E5%8F%AA%E7%94%A8%E6%A0%87%E5%87%86%E5%BA%93-2F6F6D)](ferret_mail_service.py)
[![只收不发](https://img.shields.io/badge/%E9%82%AE%E4%BB%B6-%E5%8F%AA%E6%94%B6%E4%B8%8D%E5%8F%91-BB6A42)](#它不做什么)
[![MIT](https://img.shields.io/badge/license-MIT-284B63)](LICENSE)

> 让自己的域名真的能收信：任意 `名字@你的域名` 都收得到。

## 为什么会需要它

你有一个自己的域名。注册各种服务时，你希望每个站点用一个不同的邮箱地址——这样谁把你的地址卖了，一看就知道。

托管邮箱服务能做这件事，但要么按邮箱数量收钱，要么把你的所有来信存在别人那里。而自己搭一套完整邮件服务器（Postfix + Dovecot + 反垃圾 + 证书 + ...）是另一个量级的工程，而且你其实**根本不需要发信**。

所以这个项目只做一半：**只收，不发。**

任意 `什么名字@你的域名` 直接就能收到邮件，不用提前创建。收到之后在网页里读信、复制验证码、看链接、下附件；也可以通过 HTTP API 拿。全部数据在你自己的机器上，一个 SQLite 文件。

整个服务是**一份 Python 文件 + 标准库**，没有第三方运行依赖。

## 界面

![后台预览](docs/images/dashboard.png)

## 它能做什么

- **多域名收件** — 多个主域名、子域名，以及自动创建的别名地址。
- **网页里干完事** — 检索邮件、阅读正文、一键复制验证码、查看链接、下载附件。
- **四套主题** — 天光、墨玉、素纸三套浅色配色和 `#17191d` 深灰暗色，选择会全局记住。
- **分权限的访问** — 给不同域名签发独立的管理 Token，也可以为单个别名创建"只能看这一个邮箱"的接码链接。
- **给程序用的接口** — 长轮询 API、Webhook、DNS 记录检查、容量配额、限流和操作日志。
- **自己照顾自己** — 自动备份 SQLite，并对 HTTP、SMTP、磁盘和备份状态做健康检查。

## 快速开始

```bash
cp .env.example .env
# 编辑 .env：至少要设置一个长随机的 PANEL_TOKEN、MAIL_DOMAIN 和 PUBLIC_IP
set -a && . ./.env && set +a
python3 ferret_mail_service.py
```

生产环境请按[部署教程](部署教程.md)使用非 root 用户、systemd、HTTPS 和受限文件权限。完整变量清单见 [.env.example](.env.example)。

## 公网部署需要什么

这是绕不过去的三件事，先确认再动手：

1. **固定公网 IP**，且 **TCP 25 端口可用**——很多云服务商和家宽默认封 25 端口，需要申请解封。
2. **正确的 MX / A 记录**（服务内置 DNS 检查帮你核对）。
3. **管理后台前面挂 HTTPS 反向代理**。

## 技术上值得一提的地方

**一份 Python 文件，只用标准库。** SMTP 收件、HTTP 服务、响应式后台、SQLite 存储、验证码提取和备份全在里面，没有第三方运行依赖。理由和游戏服务器那个项目一样：邮件服务是"装好就希望它三年别出事"的东西，依赖越少越安全。

**分享链接的 Token 不进服务器日志。** 单别名接码链接把能力 Token 放在 URL 的 **fragment**（`#` 后面）——fragment 不会被浏览器发给服务器，因此不会出现在反向代理和访问日志里。页面读到之后立即换成 HttpOnly 会话 Cookie。旧的"路径里带 Token"式链接需要重新导出。

**长轮询而不是让你狂刷。** `wait` 参数让调用方挂在那里等新邮件，而不是每秒来一次 `GET`。配合稳定的邮件 `id` 做去重。

**四类健康检查是分开的。** HTTP、SMTP、磁盘和备份状态各自独立上报——"服务还活着"和"备份还在做"是两个问题，混在一个绿灯里没有意义。

**限流和配额是按域名的。** 容量配额、限流和操作日志都按域名维度，一个域名被刷不会拖垮其他域名。

## 它不做什么

- **不发信。** 没有 SMTP 发送、没有 SPF/DKIM 签名、不能当发件服务器用。
- 不提供 IMAP、日历，或完整邮件客户端能力。
- 不做反垃圾评分（收进来的东西你自己判断）。
- 适合：个人域名收件、测试环境、验证码归档、小型内部工具。
  不适合：作为主邮箱、团队协作邮箱或对外发信服务。

## 隐私与安全

仓库里不含任何部署数据库、邮件、凭据、真实域名、服务器地址或生产日志。

**永远不要提交** `.env`、SQLite 文件、备份、下载的附件，或来自真实收件箱的截图。

## 更多文档

[部署教程](部署教程.md) · [技术文档](技术文档.md) · [配置模板](.env.example) · [版本变更](CHANGELOG.md) · [参与开发](CONTRIBUTING.md) · [安全策略](SECURITY.md)

## 许可

MIT License，见 [LICENSE](LICENSE)。
