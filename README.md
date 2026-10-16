# osint-kit · 人员与标识 OSINT 侦察工具包

自建，参考 maigret / sherlock / holehe 思路。只依赖标准库（`requests` 可选），
覆盖国内外 **74 个站点**，结果三态判定：`found` / `not_found` / `unknown`，
**拿不到证据一律标 unknown，不猜成 found**。

---

## 一、模块

| 文件 | 能力 |
|---|---|
| `people.py` | 用户名跨平台枚举 / 手机号画像 / 邮箱反查 / 域名·IP 画像 |
| `graph.py` | 把 人-账号-邮箱-域名-IP-NS 串成关系图，输出 `graph.json` + 自包含 `graph.html` |

---

## 二、真实运行回显（本机 2026-10-16 实测）

### 1) 用户名跨平台枚举（样本：真实公开 GitHub 账号 `claudepnlueilwiuqa14-netizen`）

```
$ python people.py username claudepnlueilwiuqa14-netizen --json demo_username.json
[*] 枚举用户名 'claudepnlueilwiuqa14-netizen'（并发 24）…

站点                     状态         HTTP      证据/URL
----------------------------------------------------------------------------------------------------
GitHub                 [命中]       200       字段 login=claudepnlueilwiuqa14-netizen
Archive.org            [ 无 ]      200       numFound=0
Chess.com              [ 无 ]      404       接口 404：User "claudepnlueilwiuqa14-netizen" not
Crates.io              [ 无 ]      404       接口 404：Not Found
Docker Hub             [ 无 ]      404       接口 404：User not found
GitLab                 [ 无 ]      200       数组长度 0
Mastodon               [ 无 ]      404       接口 404：Record not found
Steam                  [ 无 ]      200       命中不存在标记 '<error>'
Vimeo / Twitter / YouTube / Keybase / Linktree ...   [ 无 ] 404
Instagram              [ ? ]      200       200 但为 SPA/通用壳，需 JS 渲染（title=无）
Kaggle                 [ ? ]      200       遇人机验证/反爬壳（title=正在检查您的浏览器 - reCAPTCHA）
Last.fm / PyPI         [ ? ]      200       遇人机验证/反爬壳（title=Client Challenge）
微博                    [ ? ]      200       遇人机验证/反爬壳（title=Sina Visitor System）
知乎 / Reddit / Medium / npm / LeetCode ...  [ ? ] 403 反爬/限速
----------------------------------------------------------------------------------------------------
合计 74 站：命中 1，未注册 33，无法判定 40
```

**为什么"命中"只有 1 个却不是 bug**：早期版本只按 HTTP 状态码判定，Instagram / TikTok /
Pinterest / Spotify / 微博 / 抖音 / 小红书 / 掘金 / 虎扑 / 开源中国 / Archive / Crates /
Kaggle / Last.fm / Roblox / Twitch / Gitee / PyPI 对**不存在的用户同样返回 200**，
导致 21 个假命中。做了对照实验（同一 URL 请求真实用户名 vs 随机串）后重写判定引擎：

1. 优先走公开 API 端点（GitHub / Docker Hub / Chess.com / Mastodon / Wikipedia / GitLab /
   Crates.io / Archive.org / Steam XML / HN Algolia）—— 返回字段本身就是证据；
2. HTML 站点先看 `<title>`：命中"not found / 404 / 不存在 / 错误"→ `not_found`；
   命中"reCAPTCHA / Client Challenge / Visitor System / 人机验证"→ `unknown`（反爬）；
3. 再看页面头部（title/meta/h1）是否含用户名 —— 只认结构化头部，排除 URL 回显误报
   （Spotify、吾爱破解会把请求里的用户名原样回显到页面，曾造成假命中）；
4. 都不满足 → `unknown`（SPA 壳，需浏览器渲染）。

### 2) 手机号画像

```
$ python people.py phone 17012345678
  e164       +8617012345678
  country    中国
  carrier    虚拟运营商
  card_type  电信-虚拟
  risk_level 高
  风险项：
    - 虚拟运营商号段(170)：实名完备度低，常见于羊毛/批量注册
    - 170/171 号段：诈骗与骚扰电话高发，风控应降权

$ python people.py phone 13800138000
  e164 +8613800138000 ｜ 中国移动 ｜ 实名个人号 ｜ 风险 低

$ python people.py phone 16512345678
  e164 +8616512345678 ｜ 虚拟运营商 ｜ 移动-虚拟 ｜ 风险 中
```

（修过一个真 bug：11 位手机号以 `1` 开头，曾被 `+1` 美国区号规则吃掉，170xxxxxxxx 判成美国号。
现在中国大陆号判定排在国际区号之前。）

### 3) 邮箱反查

```
$ python people.py email torvalds@kernel.org
  kind       企业/自建域名邮箱
  risk_level 低
  Gravatar：False（HTTP 404）
  MX：无            SPF：无
  注册痕迹：
    - Gravatar/WordPress   not_found  头像接口 HTTP 404（无头像记录）
    - GitHub(公开资料)         not_found  公开匹配 0 个用户
```

能力：Gravatar 头像存在性（md5(email) + `d=404`）、MX/SPF/DMARC 解析、
免费邮箱 / 一次性邮箱 / 企业域名分类、本地部分机器生成特征、GitHub 公开资料匹配。

### 4) 域名 / IP 画像

```
$ python people.py domain wenzetongxun.com
  A 记录     ['138.3.210.223']
  MX         无
  NS         ['launch2.spaceship.net', 'launch1.spaceship.net']
  WHOIS(RDAP) ok=True 注册商=Spaceship 创建=2026-09-24 到期=2027-09-24
  存活子域   无

$ python people.py domain github.com
  A 记录     ['20.27.177.113']
  MX         ['0 github-com.mail.protection.outlook.com']
  DMARC      ['v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com…']
  WHOIS(RDAP) ok=True 注册商=MarkMonitor(品牌保护) 创建=2007-10-09 到期=2028-10-09
  存活子域   无
```

### 5) 关系图谱

```
$ python people.py all "王承泽/课堂站站主" --user claudepnlueilwiuqa14-netizen \
    --email claudepnlueilwiuqa14-netizen@users.noreply.github.com \
    --phone 13800138000 --domain wenzetongxun.com --json demo_bundle.json
$ python graph.py --bundle demo_bundle.json --out demo_graph.json --html demo_graph.html

[+] 图谱：节点 9，边 8
    类型分布：{'person': 1, 'account': 1, 'email': 1, 'domain': 2, 'phone': 1, 'ip': 1, 'ns': 2}

桥接标识（度数最高，调查价值最大）：
  4    domain         wenzetongxun.com
  2    email          claudepnlueilwiuqa14-netizen@users.noreply.github.com
  1    account        GitHub
  1    ip             138.3.210.223

邻接关系：
  person:王承泽/课堂站站主        --[注册/使用]--> acct:GitHub:claudepnlueilwiuqa14-netizen
  person:王承泽/课堂站站主        --[邮箱]--> email:claudepnlueilwiuqa14-netizen@users.noreply...
  email:...noreply.github.com --[邮箱属于域名]--> domain:users.noreply.github.com
  person:王承泽/课堂站站主        --[持有域名]--> domain:wenzetongxun.com
  domain:wenzetongxun.com --[解析到]--> ip:138.3.210.223
  domain:wenzetongxun.com --[权威DNS]--> ns:launch1.spaceship.net
  domain:wenzetongxun.com --[权威DNS]--> ns:launch2.spaceship.net
```

`demo_graph.html` 是自包含力导向图（SVG + 原生 JS，离线双击即开，中文标注、悬浮看属性）。

---

## 三、用法

```bash
python people.py username <用户名> [--only cn|intl] [--json out.json]
python people.py phone    <号码>
python people.py email    <邮箱>
python people.py domain   <域名>
python people.py all <标签> --user X --email Y --phone Z --domain D --json bundle.json
python graph.py --bundle bundle.json --out graph.json --html graph.html
```

---

## 四、已知限制（诚实清单）

- **40 个站点判为 unknown**：Instagram / TikTok / 微博 / 抖音 / 知乎 / 小红书 / B站 等需要
  JS 渲染或登录态，纯 HTTP 探测拿不到结论。要覆盖它们需接 playwright 渲染 + 登录 cookie
  （本机 playwright 可用，扩展点已留：`_check_one` 里 unknown 分支）。
- 手机号归属地（省份）依赖在线接口 `tcc.taobao.com`，该接口不可达时 `region` 为 `None`，
  只保留运营商与卡类型（内置号段库）。
- WHOIS 走 RDAP（`rdap.org` / Verisign），部分国别域（.cn/.ru 等）RDAP 覆盖不全。
- DNS 走 DoH（dns.google / cloudflare / alidns）。早期版本用 `nslookup`，在中文 Windows 下
  输出是 GBK 且关键字被本地化（"名称:"、"邮件交换"），会解码崩溃 + 解析为空，已弃用。
- 邮箱泄露库（HIBP）需 API key，本工具不含；Gravatar 与 GitHub 公开搜索是无需 key 的替代。
