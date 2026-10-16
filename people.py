#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
people.py —— 人员 / 标识 OSINT 侦察器（自建，参考 maigret / sherlock / holehe 思路）

四个能力：
  1. username   跨平台用户名枚举（国内外 70+ 站点，三态判定 found / not_found / unknown）
  2. phone      手机号：号段归属（运营商 / 省份 / 卡类型）+ 风险标注 + 国际区号库
  3. email      邮箱反查：Gravatar 头像、MX/SPF/DMARC 解析、免费/一次性/企业邮箱分类、
                注册痕迹探测（Gravatar + 站点找回密码接口差异）
  4. domain     域名 / IP 画像：DNS(A/AAAA/MX/NS/TXT)、RDAP/WHOIS、IP 地理与 ASN、子域线索

设计原则：
  * 只依赖标准库（可选 requests，缺失时 urllib 兜底），不装任何包即可跑。
  * 永远给三态结果，不编造：拿不到证据一律 unknown，绝不猜成 found。
  * 并发探测，单站超时独立，坏站不影响整体。

用法：
  python people.py username torvalds
  python people.py username 抖音昵称 --only cn --json out.json
  python people.py phone 17012345678
  python people.py email someone@example.com
  python people.py domain example.com
  python people.py all 王承泽 --user claudepnlueilwiuqa14-netizen --email a@b.com --phone 13800138000
"""
import os
import re
import sys
import json
import time
import socket
import hashlib
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote as urllib_quote

PROXY = os.environ.get("OSINT_PROXY", "http://127.0.0.1:7897")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
TIMEOUT = float(os.environ.get("OSINT_TIMEOUT", "8"))

try:
    import requests  # 可选加速
except Exception:
    requests = None


# ============================================================================
# 0. HTTP 层
# ============================================================================
def http_get(url, headers=None, allow_redirects=True, timeout=None):
    """返回 dict: {ok, status, url, text, err}。绝不抛异常。"""
    timeout = timeout or TIMEOUT
    hdr = {"User-Agent": UA,
           "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
           "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
    if headers:
        hdr.update(headers)
    t0 = time.time()
    try:
        if requests is not None:
            r = requests.get(url, headers=hdr, timeout=timeout,
                             allow_redirects=allow_redirects,
                             proxies={"http": PROXY, "https": PROXY})
            return {"ok": r.status_code < 400, "status": r.status_code, "url": r.url,
                    "text": r.text[:60000], "err": None, "ms": int((time.time() - t0) * 1000)}
        import urllib.request
        req = urllib.request.Request(url, headers=hdr)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
        r = opener.open(req, timeout=timeout)
        return {"ok": True, "status": r.status, "url": r.geturl(),
                "text": r.read(60000).decode("utf-8", "ignore"), "err": None,
                "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        code = getattr(e, "code", None)
        return {"ok": False, "status": code or 0, "url": url, "text": "",
                "err": "%s:%s" % (type(e).__name__, str(e)[:60]),
                "ms": int((time.time() - t0) * 1000)}


# ============================================================================
# 1. 用户名跨平台枚举
# ============================================================================
# 每个站点: name, region, url 模板, 判定方式
#   kind=status   : 200=found, 404=not_found（其它=unknown）
#   kind=json     : 用 json_path 取值判定
#   kind=keyword  : 页面含 must 文本=found；含 none 文本=not_found
# 软 404 / 反爬 / SPA 壳识别词表（实测得出：Instagram、TikTok、Pinterest、Spotify、
# 微博、抖音、小红书、掘金、虎扑、开源中国、Archive、Crates、Kaggle、Last.fm、Roblox、
# Twitch、Gitee、PyPI 等对"不存在的用户"同样返回 HTTP 200，仅靠状态码会 100% 误报）
TITLE_NOTFOUND = ["not found", "page not found", "404", "doesn't exist", "does not exist",
                  "no such user", "user not found", "isn't available", "couldn't find",
                  "页面不存在", "用户不存在", "找不到", "不存在", "无法访问", "出错", "错误"]
BLOCK_HINTS = ["client challenge", "recaptcha", "just a moment", "checking your browser",
               "attention required", "captcha", "visitor system", "verify your",
               "人机验证", "访问验证", "安全验证"]

SITES = [
    # ---------- 国际：有公开 API / 强判定端点（证据最硬）----------
    ("GitHub", "intl", "https://api.github.com/users/{}", "api", {"cmp": {"key": "login"}}),
    ("Docker Hub", "intl", "https://hub.docker.com/v2/users/{}/", "api", {}),
    ("Chess.com", "intl", "https://api.chess.com/pub/player/{}", "api", {}),
    ("Mastodon", "intl", "https://mastodon.social/api/v1/accounts/lookup?acct={}", "api", {}),
    ("Wikipedia", "intl", "https://en.wikipedia.org/w/api.php?action=query&list=users"
                          "&ususers={}&format=json", "api", {"missing": True}),
    ("GitLab", "intl", "https://gitlab.com/api/v4/users?username={}", "api", {"array": True}),
    ("Crates.io", "intl", "https://crates.io/api/v1/users/{}", "api", {}),
    ("Archive.org", "intl", "https://archive.org/advancedsearch.php?q=uploader:{}"
                            "&fl%5B%5D=identifier&rows=1&output=json", "api", {"numfound": True}),
    ("Steam", "intl", "https://steamcommunity.com/id/{}/?xml=1", "keyword",
     {"must": ["steamID64"], "none": ["<error>"]}),
    ("HackerNews", "intl", "https://hn.algolia.com/api/v1/users/{}", "api",
     {"cmp": {"key": "username"}}),

    # ---------- 国际：HTML 状态判定 ----------
    ("Bitbucket", "intl", "https://bitbucket.org/{}/", "status", {}),
    ("npm", "intl", "https://www.npmjs.com/~{}", "status", {}),
    ("PyPI", "intl", "https://pypi.org/user/{}/", "status", {}),
    ("Packagist", "intl", "https://packagist.org/users/{}/", "status", {}),
    ("SourceForge", "intl", "https://sourceforge.net/u/{}/profile/", "status", {}),
    ("Twitter/X", "intl", "https://x.com/{}", "status", {}),
    ("Instagram", "intl", "https://www.instagram.com/{}/", "status", {}),
    ("Facebook", "intl", "https://www.facebook.com/{}", "status", {}),
    ("LinkedIn", "intl", "https://www.linkedin.com/in/{}", "status", {}),
    ("Reddit", "intl", "https://www.reddit.com/user/{}/", "status", {}),
    ("Telegram", "intl", "https://t.me/{}", "status", {}),
    ("YouTube", "intl", "https://www.youtube.com/@{}", "status", {}),
    ("Twitch", "intl", "https://www.twitch.tv/{}", "status", {}),
    ("TikTok", "intl", "https://www.tiktok.com/@{}", "status", {}),
    ("Pinterest", "intl", "https://www.pinterest.com/{}/", "status", {}),
    ("Tumblr", "intl", "https://{}.tumblr.com", "status", {}),
    ("Medium", "intl", "https://medium.com/@{}", "status", {}),
    ("Substack", "intl", "https://{}.substack.com", "status", {}),
    ("Flickr", "intl", "https://www.flickr.com/people/{}/", "status", {}),
    ("Vimeo", "intl", "https://vimeo.com/{}", "status", {}),
    ("SoundCloud", "intl", "https://soundcloud.com/{}", "status", {}),
    ("DeviantArt", "intl", "https://www.deviantart.com/{}", "status", {}),
    ("Behance", "intl", "https://www.behance.net/{}", "status", {}),
    ("Dribbble", "intl", "https://dribbble.com/{}", "status", {}),
    ("CodePen", "intl", "https://codepen.io/{}", "status", {}),
    ("StackOverflow", "intl", "https://stackoverflow.com/users/{}", "status", {}),
    ("Keybase", "intl", "https://keybase.io/{}", "status", {}),
    ("LeetCode", "intl", "https://leetcode.com/u/{}/", "status", {}),
    ("Kaggle", "intl", "https://www.kaggle.com/{}", "status", {}),
    ("Linktree", "intl", "https://linktr.ee/{}", "status", {}),
    ("Patreon", "intl", "https://www.patreon.com/{}", "status", {}),
    ("Roblox", "intl", "https://www.roblox.com/user.aspx?username={}", "status", {}),
    ("Strava", "intl", "https://www.strava.com/athletes/{}", "status", {}),
    ("Goodreads", "intl", "https://www.goodreads.com/{}", "status", {}),
    ("Last.fm", "intl", "https://www.last.fm/user/{}", "status", {}),
    ("Spotify", "intl", "https://open.spotify.com/user/{}", "status", {}),
    ("TryHackMe", "intl", "https://tryhackme.com/p/{}", "status", {}),
    ("Bugcrowd", "intl", "https://bugcrowd.com/{}", "status", {}),
    ("HackerOne", "intl", "https://hackerone.com/{}", "status", {}),

    # ---------- 国内 ----------
    ("Gitee码云", "cn", "https://gitee.com/api/v5/users/{}", "api", {}),
    ("知乎", "cn", "https://www.zhihu.com/api/v4/members/{}", "api", {}),
    ("哔哩哔哩", "cn", "https://space.bilibili.com/{}", "status", {}),
    ("微博", "cn", "https://weibo.com/u/{}", "status", {}),
    ("豆瓣", "cn", "https://www.douban.com/people/{}/", "status", {}),
    ("抖音", "cn", "https://www.douyin.com/user/{}", "status", {}),
    ("小红书", "cn", "https://www.xiaohongshu.com/user/profile/{}", "status", {}),
    ("快手", "cn", "https://www.kuaishou.com/profile/{}", "status", {}),
    ("CSDN", "cn", "https://blog.csdn.net/{}", "status", {}),
    ("掘金", "cn", "https://juejin.cn/user/posts?user_id={}", "status", {}),
    ("简书", "cn", "https://www.jianshu.com/u/{}", "status", {}),
    ("博客园", "cn", "https://home.cnblogs.com/u/{}/", "status", {}),
    ("SegmentFault", "cn", "https://segmentfault.com/u/{}", "status", {}),
    ("V2EX", "cn", "https://v2ex.com/u/{}", "status", {}),
    ("吾爱破解", "cn", "https://www.52pojie.cn/home.php?mod=space&username={}", "status", {}),
    ("开源中国", "cn", "https://my.oschina.net/{}", "status", {}),
    ("酷安", "cn", "https://www.coolapk.com/u/{}", "status", {}),
    ("网易云音乐", "cn", "https://music.163.com/#/user/home?id={}", "status", {}),
    ("百度贴吧", "cn", "https://tieba.baidu.com/home/main?un={}", "status", {}),
    ("虎扑", "cn", "https://bbs.hupu.com/{}", "status", {}),
    ("什么值得买", "cn", "https://www.smzdm.com/u/{}/", "status", {}),
    ("起点中文网", "cn", "https://my.qidian.com/user/{}", "status", {}),
    ("洛谷", "cn", "https://www.luogu.com.cn/user/{}", "status", {}),
    ("CTFtime", "intl", "https://ctftime.org/user/{}", "status", {}),
    ("阿里云开发者", "cn", "https://developer.aliyun.com/profile/{}", "status", {}),
]


def _title_of(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    return m.group(1).strip()[:80] if m else ""


def _meta_blob(html):
    """只取 title / meta / h1 里的文本。
    为什么：Spotify、吾爱破解、Roblox 等会把请求 URL 里的用户名原样回显进页面，
    直接搜整个 HTML 会 100% 误报。只认结构化头部字段才是真证据。"""
    parts = [_title_of(html)]
    for m in re.finditer(r"<meta[^>]+(?:name|property)=[\"']([^\"']+)[\"'][^>]*"
                         r"(?:content=[\"']([^\"']*)[\"'])?[^>]*>", html, re.I):
        parts.append((m.group(2) or "")[:200])
    for m in re.finditer(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I):
        parts.append(re.sub(r"<[^>]+>", "", m.group(1))[:200])
    return " \n ".join(parts)


def _check_one(site, username):
    name, region, tpl, kind, opt = site
    url = tpl.replace("{}", username)
    r = http_get(url)
    res = {"site": name, "region": region, "url": url, "status": r["status"],
           "state": "unknown", "evidence": "", "ms": r["ms"]}
    if r["err"] and r["status"] == 0:
        res["evidence"] = "网络错误 " + r["err"]
        return res

    # ---------- API 型：200=存在 / 404=不存在，另有字段级判定 ----------
    if kind == "api":
        if r["status"] == 404:
            res["state"] = "not_found"
            res["evidence"] = "接口 404"
            try:
                j = json.loads(r["text"])
                msg = j.get("message") or (j.get("errors") or [{}])[0].get("detail") \
                      or j.get("error") or ""
                if msg:
                    res["evidence"] = "接口 404：%s" % str(msg)[:60]
            except Exception:
                pass
            return res
        if r["status"] in (401, 403, 429):
            res["evidence"] = "接口 HTTP %s（需认证/限流）" % r["status"]
            return res
        if r["status"] != 200:
            res["evidence"] = "接口 HTTP %s" % r["status"]
            return res
        try:
            j = json.loads(r["text"])
        except Exception:
            res["evidence"] = "200 但非 JSON"
            return res
        cmp_ = opt.get("cmp")
        if cmp_:
            ok = str(j.get(cmp_["key"], "")).lower() == username.lower()
            res["state"] = "found" if ok else "not_found"
            res["evidence"] = ("字段 %s=%s" % (cmp_["key"], j.get(cmp_["key"])))[:60]
            return res
        if opt.get("missing"):     # Wikipedia: users[0] 含 missing 即不存在
            users = (j.get("query") or {}).get("users") or []
            ok = bool(users) and "missing" not in users[0]
            res["state"] = "found" if ok else "not_found"
            res["evidence"] = "users[0]=%s" % str(users[0])[:60] if users else "空结果"
            return res
        if opt.get("array"):       # GitLab: 数组非空即存在
            ok = isinstance(j, list) and len(j) > 0
            res["state"] = "found" if ok else "not_found"
            res["evidence"] = "数组长度 %d" % (len(j) if isinstance(j, list) else -1)
            return res
        if opt.get("numfound"):    # Archive.org: numFound>0 即上传过内容
            n = int((j.get("response") or {}).get("numFound", 0))
            res["state"] = "found" if n > 0 else "not_found"
            res["evidence"] = "numFound=%d" % n
            return res
        res["state"] = "found"
        res["evidence"] = "接口 200 有数据"
        return res

    # ---------- keyword 型（含 XML）----------
    if kind == "keyword":
        txt = r["text"]
        if r["status"] >= 400 and r["status"] != 200:
            res["state"] = "not_found" if r["status"] == 404 else "unknown"
            res["evidence"] = "HTTP %s" % r["status"]
            return res
        for nk in opt.get("none", []):
            if nk.lower() in txt.lower():
                res["state"] = "not_found"
                res["evidence"] = "命中不存在标记 %r" % nk[:24]
                return res
        if all(m.lower() in txt.lower() for m in opt.get("must", [])):
            res["state"] = "found"
            res["evidence"] = "命中特征串 %s" % ",".join(opt.get("must", []))[:30]
        else:
            res["state"] = "unknown"
            res["evidence"] = "特征串未命中"
        return res

    # ---------- status 型：软 404 / 反爬 / SPA 三重过滤 ----------
    if r["status"] == 404:
        res["state"] = "not_found"
        res["evidence"] = "HTTP 404"
        return res
    if r["status"] in (403, 429, 999):
        res["evidence"] = "HTTP %s（反爬/限速）" % r["status"]
        return res
    if r["status"] in (301, 302, 303, 307, 308):
        res["evidence"] = "跳转 %s（多半是登录墙）" % r["status"]
        return res
    if r["status"] != 200:
        res["evidence"] = "HTTP %s" % r["status"]
        return res

    html = r["text"]
    title = _title_of(html)
    tl = title.lower()
    if any(b in tl for b in BLOCK_HINTS):
        res["evidence"] = "遇人机验证/反爬壳（title=%s）" % title[:30]
        return res
    if any(t in tl for t in TITLE_NOTFOUND):
        res["state"] = "not_found"
        res["evidence"] = "软404（title=%s）" % title[:40]
        return res
    # 强证据：title/meta/h1 里出现用户名（排除 URL 回显误报）
    if len(username) >= 4 and username.lower() in _meta_blob(html).lower():
        res["state"] = "found"
        res["evidence"] = "HTTP 200 且页面头部(title/meta/h1)含用户名"
        return res
    res["state"] = "unknown"
    res["evidence"] = "200 但为 SPA/通用壳，需 JS 渲染（title=%s）" % (title[:26] or "无")
    return res


def enum_username(username, region=None, workers=24, sites=None):
    pool = SITES
    if region:
        pool = [s for s in pool if s[1] == region]
    if sites:
        want = set(x.lower() for x in sites)
        pool = [s for s in pool if s[0].lower() in want]
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_check_one, s, username): s for s in pool}
        for f in as_completed(futs):
            try:
                out.append(f.result())
            except Exception as e:
                s = futs[f]
                out.append({"site": s[0], "region": s[1], "url": "", "status": 0,
                            "state": "unknown", "evidence": "异常 " + str(e), "ms": 0})
    order = {"found": 0, "not_found": 1, "unknown": 2}
    out.sort(key=lambda x: (order.get(x["state"], 3), x["site"]))
    return out


# ============================================================================
# 2. 手机号
# ============================================================================
# 中国大陆号段（前三位 -> 运营商）。省份归属需要 7 位号段库，本文件内置常见段 + 在线兜底。
CN_PREFIX = {}
for _p in ["130", "131", "132", "155", "156", "175", "176", "185", "186", "166", "196", "145", "146"]:
    CN_PREFIX[_p] = "中国联通"
for _p in ["133", "149", "153", "173", "174", "177", "180", "181", "189", "190", "191", "193", "199", "141"]:
    CN_PREFIX[_p] = "中国电信"
for _p in ["134", "135", "136", "137", "138", "139", "147", "148", "150", "151", "152", "157",
           "158", "159", "172", "178", "182", "183", "184", "187", "188", "195", "197", "198"]:
    CN_PREFIX[_p] = "中国移动"
for _p in ["170", "171", "162", "165", "167"]:
    CN_PREFIX[_p] = "虚拟运营商"
CN_PREFIX["144"] = "中国广电(物联网)"
CN_PREFIX["192"] = "中国广电"

# 虚拟运营商号段（风险标注用）
MVNO_SEG = {
    "1700": "电信-虚拟", "1701": "电信-虚拟", "1702": "电信-虚拟",
    "1703": "移动-虚拟", "1705": "移动-虚拟", "1706": "移动-虚拟",
    "1704": "联通-虚拟", "1707": "联通-虚拟", "1708": "联通-虚拟", "1709": "联通-虚拟",
    "1710": "联通-虚拟", "1711": "联通-虚拟", "1712": "联通-虚拟", "1713": "联通-虚拟",
    "1714": "联通-虚拟", "1715": "联通-虚拟", "1716": "联通-虚拟", "1717": "联通-虚拟",
    "1718": "联通-虚拟", "1719": "联通-虚拟", "162": "电信-虚拟", "165": "移动-虚拟",
    "167": "联通-虚拟",
}
# 非个人号（企业/客服/物联）
SPECIAL = {"400": "企业客服热线(主被叫分摊)", "800": "企业客服热线(被叫付费)",
           "95": "银行/保险客服专线", "96": "省级客服短号", "1": "服务短号(如10086)"}

# 国际区号
COUNTRY_CODE = {
    "1": "美国/加拿大", "7": "俄罗斯/哈萨克", "20": "埃及", "27": "南非", "30": "希腊",
    "31": "荷兰", "32": "比利时", "33": "法国", "34": "西班牙", "36": "匈牙利",
    "39": "意大利", "40": "罗马尼亚", "41": "瑞士", "43": "奥地利", "44": "英国",
    "45": "丹麦", "46": "瑞典", "47": "挪威", "48": "波兰", "49": "德国", "51": "秘鲁",
    "52": "墨西哥", "53": "古巴", "54": "阿根廷", "55": "巴西", "56": "智利",
    "57": "哥伦比亚", "58": "委内瑞拉", "60": "马来西亚", "61": "澳大利亚", "62": "印尼",
    "63": "菲律宾", "64": "新西兰", "65": "新加坡", "66": "泰国", "81": "日本",
    "82": "韩国", "84": "越南", "86": "中国", "90": "土耳其", "91": "印度",
    "92": "巴基斯坦", "93": "阿富汗", "94": "斯里兰卡", "95": "缅甸", "98": "伊朗",
    "212": "摩洛哥", "213": "阿尔及利亚", "216": "突尼斯", "218": "利比亚",
    "234": "尼日利亚", "254": "肯尼亚", "255": "坦桑尼亚", "351": "葡萄牙",
    "352": "卢森堡", "353": "爱尔兰", "354": "冰岛", "358": "芬兰", "359": "保加利亚",
    "370": "立陶宛", "371": "拉脱维亚", "372": "爱沙尼亚", "380": "乌克兰",
    "381": "塞尔维亚", "420": "捷克", "421": "斯洛伐克", "852": "香港", "853": "澳门",
    "855": "柬埔寨", "856": "老挝", "880": "孟加拉", "886": "台湾", "960": "马尔代夫",
    "961": "黎巴嫩", "962": "约旦", "963": "叙利亚", "964": "伊拉克", "965": "科威特",
    "966": "沙特", "971": "阿联酋", "972": "以色列", "974": "卡塔尔", "975": "不丹",
    "977": "尼泊尔", "992": "塔吉克", "993": "土库曼", "994": "阿塞拜疆",
    "995": "格鲁吉亚", "996": "吉尔吉斯", "998": "乌兹别克",
}


def _online_phone_lookup(digits):
    """在线归属地兜底（淘宝老接口），失败返回 None。"""
    try:
        r = http_get("https://tcc.taobao.com/cc/json/mobile_tel_segment.htm?tel=" + digits,
                     timeout=6)
        if r["status"] == 200 and "catName" in r["text"]:
            txt = r["text"]
            def gv(k):
                m = re.search(k + r"\s*:\s*'([^']*)'", txt)
                return m.group(1) if m else ""
            return {"province": gv("province"), "carrier": gv("catName"),
                    "source": "tcc.taobao.com"}
    except Exception:
        pass
    return None


def phone_profile(raw):
    digits = re.sub(r"[^\d+]", "", raw)
    body = digits.lstrip("+")
    info = {"input": raw, "e164": digits if digits.startswith("+") else None,
            "digits": body, "country": None, "carrier": None, "region": None,
            "card_type": None, "risk": [], "risk_level": "低", "source": []}
    if not info["e164"]:
        for n in (1, 2, 3, 4):
            if COUNTRY_CODE.get(body[:n]) and len(body) > n + 4:
                info["e164"] = "+" + body[:n] + body[n:]
                break
    if len(body) == 11 and body.startswith("1"):
        info["e164"] = "+86" + body

    # 中国大陆号优先判定：11 位且 1 开头（这条必须排在区号之前，
    # 否则 "1" 会被 +1 美国区号吃掉 —— 170xxxxxxxx 曾因此被误判成美国号码）
    if len(body) == 11 and body.startswith("1"):
        cn, cc = body, "86"
        info["country"] = "中国"
    elif body.startswith("86") and len(body) == 13:
        cn, cc = body[2:], "86"
        info["country"] = "中国"
    else:
        cn, cc = None, None
        for n in (4, 3, 2, 1):
            if COUNTRY_CODE.get(body[:n]) and len(body) > n + 4:
                cc = body[:n]
                info["country"] = COUNTRY_CODE[cc]
                break
    if cc and not info.get("country"):
        info["country"] = COUNTRY_CODE.get(cc)

    if cn:
        p3, p4 = cn[:3], cn[:4]
        info["carrier"] = CN_PREFIX.get(p3)
        info["card_type"] = MVNO_SEG.get(p4) or MVNO_SEG.get(p3) or "实名个人号"
        if info["carrier"] == "虚拟运营商":
            info["risk"].append("虚拟运营商号段(%s)：实名完备度低，常见于羊毛/批量注册" % p3)
        if p3 in ("170", "171"):
            info["risk"].append("170/171 号段：诈骗与骚扰电话高发，风控应降权")
        if cn.startswith("144") or cn.startswith("141"):
            info["risk"].append("物联网卡号段：非语音号，不可用于实名人与人联系")
        if cn.startswith("192"):
            info["risk"].append("中国广电号段：新号段，部分平台白名单未覆盖")
        onl = _online_phone_lookup(cn)
        if onl:
            info["region"] = onl.get("province") or None
            info["carrier"] = info["carrier"] or onl.get("carrier")
            info["source"].append("tcc.taobao.com")
        info["source"].append("内置号段库")
    else:
        for s in ("400", "800", "95", "96"):
            if body.startswith(s):
                info["card_type"] = SPECIAL.get(s)
                info["risk"].append("非个人号码：%s" % SPECIAL.get(s))
        if not info["card_type"]:
            info["risk"].append("未识别出归属地/运营商（号段库未覆盖或非中国号码）")

    if len(body) < 7 or len(body) > 15:
        info["risk"].append("号码长度异常（%d 位），可能是无效号" % len(body))
    if len(set(body)) == 1:
        info["risk"].append("全相同数字，测试号概率极高")

    n = len(info["risk"])
    info["risk_level"] = "高" if n >= 2 else ("中" if n == 1 else "低")
    return info


# ============================================================================
# 3. 邮箱反查
# ============================================================================
FREE_MAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
             "icloud.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
             "mail.com", "zoho.com", "yandex.com", "qq.com", "163.com", "126.com",
             "sina.com", "sohu.com", "139.com", "189.cn", "21cn.com", "yeah.net",
             "aliyun.com", "foxmail.com", "vip.qq.com", "wo.cn", "tom.com"}
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
              "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
              "getnada.com", "maildrop.cc", "temp-mail.org", "fakeinbox.com",
              "33mail.com", "mailnesia.com", "dispostable.com", "mintemail.com",
              "emailondeck.com", "mohmal.com", "armyspy.com", "dayrep.com"}
# 注册痕迹探测站点（利用找回密码/存在性接口的差异）
PROBE_SITES = [
    ("GitHub", "https://api.github.com/search/users?q={email}+in:email"),
    ("Gravatar", "GRAVATAR"),
]


def email_profile(addr, do_probe=True):
    addr = addr.strip().lower()
    m = re.match(r"^([^@]+)@([^@]+)$", addr)
    out = {"email": addr, "valid_format": bool(m), "domain": None, "local": None,
           "kind": None, "gravatar": None, "dns": None, "registrations": [],
           "risk": [], "risk_level": "低"}
    if not m:
        out["risk"].append("邮箱格式非法")
        out["risk_level"] = "中"
        return out
    local, dom = m.group(1), m.group(2)
    out["local"], out["domain"] = local, dom
    if dom in FREE_MAIL:
        out["kind"] = "免费邮箱"
    elif dom in DISPOSABLE:
        out["kind"] = "一次性/临时邮箱"
        out["risk"].append("一次性邮箱域名(%s)：批量注册/薅羊毛特征" % dom)
    else:
        out["kind"] = "企业/自建域名邮箱"
    if re.match(r"^\d{6,}$", local):
        out["risk"].append("纯数字本地部分，机器生成特征")
    if len(local) >= 20 and re.search(r"\d{6,}", local):
        out["risk"].append("本地部分长且含长数字串，疑似随机生成")

    # --- Gravatar（md5(email)）---
    h = hashlib.md5(addr.encode("utf-8")).hexdigest()
    g = http_get("https://www.gravatar.com/avatar/%s?d=404&s=80" % h, timeout=8)
    out["gravatar"] = {"url": "https://www.gravatar.com/avatar/%s" % h,
                       "exists": g["status"] == 200, "http": g["status"]}
    if g["status"] == 200:
        out["registrations"].append({"site": "Gravatar/WordPress", "state": "found",
                                     "evidence": "头像接口 HTTP 200（该邮箱曾设头像）"})
    elif g["status"] == 404:
        out["registrations"].append({"site": "Gravatar/WordPress", "state": "not_found",
                                     "evidence": "头像接口 HTTP 404（无头像记录）"})
    else:
        out["registrations"].append({"site": "Gravatar/WordPress", "state": "unknown",
                                     "evidence": "HTTP %s" % g["status"]})

    # --- 域名邮件 DNS 画像 ---
    out["dns"] = dns_records(dom)

    if do_probe:
        # GitHub 公开搜索：邮箱出现在公开提交/资料中
        try:
            r = http_get("https://api.github.com/search/users?q=%s+in:email" % addr, timeout=8)
            if r["status"] == 200:
                j = json.loads(r["text"])
                n = j.get("total_count", 0)
                out["registrations"].append({
                    "site": "GitHub(公开资料)", "state": "found" if n else "not_found",
                    "evidence": "公开匹配 %d 个用户" % n})
            else:
                out["registrations"].append({"site": "GitHub(公开资料)", "state": "unknown",
                                             "evidence": "HTTP %s（未认证时限流）" % r["status"]})
        except Exception as e:
            out["registrations"].append({"site": "GitHub(公开资料)", "state": "unknown",
                                         "evidence": str(e)[:60]})

    n = len(out["risk"])
    out["risk_level"] = "高" if n >= 2 else ("中" if n == 1 else "低")
    return out


# ============================================================================
# 4. 域名 / IP 画像
# ============================================================================
def _nslookup(name, rtype):
    """用系统 nslookup 解析任意记录类型（Windows/Linux 通用，避开 dnspython 依赖）。"""
    try:
        p = subprocess.run(["nslookup", "-type=%s" % rtype, name],
                           capture_output=True, timeout=15)
        # 中文 Windows 的 nslookup 输出是 GBK，直接 text=True(utf-8) 会 UnicodeDecodeError
        raw = (p.stdout or b"") + (p.stderr or b"")
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            txt = raw.decode("gbk", errors="ignore")
        vals = []
        for line in txt.splitlines():
            ls = line.strip()
            if ls.lower().startswith((name.lower() + "\t", name.lower() + " ")) or \
               ("\t" in ls and "internet address" in ls.lower()):
                v = ls.split("=")[-1].strip() if "=" in ls else ls.split("\t")[-1].strip()
                if v and v not in vals:
                    vals.append(v)
        return {"ok": True, "values": vals, "raw": txt[:1200]}
    except Exception as e:
        return {"ok": False, "values": [], "raw": str(e)[:120]}


DOH_ENDPOINTS = ["https://dns.google/resolve",
                 "https://cloudflare-dns.com/dns-query",
                 "https://dns.alidns.com/resolve"]


def _doh(name, rtype):
    """DNS-over-HTTPS。比 nslookup 可靠：跨平台、返回 JSON、中文 Windows 下不会
    因 GBK 输出/本地化关键字（"名称:"/"邮件交换"）解析失败。"""
    for ep in DOH_ENDPOINTS:
        try:
            r = http_get("%s?name=%s&type=%s" % (ep, urllib_quote(name), rtype),
                         headers={"accept": "application/dns-json"}, timeout=8)
            if r["status"] != 200:
                continue
            j = json.loads(r["text"])
            if j.get("Status") not in (0, "0", None):
                return {"ok": True, "values": [], "nxdomain": True, "via": ep}
            vals = []
            for a in j.get("Answer") or []:
                d = a.get("data") or ""
                d = d.strip('"').rstrip(".")
                if d and d not in vals:
                    vals.append(d)
            if vals:
                return {"ok": True, "values": vals, "nxdomain": False, "via": ep}
        except Exception:
            continue
    return {"ok": False, "values": [], "nxdomain": False, "via": None}


def dns_records(domain):
    res = {}
    for rt in ("A", "AAAA", "MX", "NS", "TXT"):
        r = _doh(domain, rt)
        res[rt] = r["values"][:8]
    res["_resolver"] = r.get("via")
    txts = [t for t in res.get("TXT", []) if "spf" in t.lower() or t.lower().startswith("v=")]
    res["spf"] = txts[0] if txts else None
    res["dmarc"] = _doh("_dmarc." + domain, "TXT")["values"][:2]
    res["nxdomain"] = _doh(domain, "A").get("nxdomain", False)
    return res


# RDAP 返回的注册商常常只是 IANA 数字 ID，落到报告里没法用
IANA_REGISTRAR = {
    "292": "MarkMonitor(品牌保护)", "1910": "Cloudflare", "1068": "GoDaddy",
    "1449": "阿里云万网", "1599": "Gandi", "1636": "Namecheap", "1200": "Name.com",
    "3862": "Spaceship", "1479": "Google Domains→Squarespace", "376": "Network Solutions",
    "303": "Tucows", "9998": "西数/西部数码", "9999": "新网", "608": "eName(易名)",
    "1595": "HiChina→阿里云", "1556": "成都西维", "1626": "22net", "69": "MarkMonitor",
}


def rdap_whois(domain):
    """RDAP：无需 whois 命令，官方 registry 提供的 HTTPS WHOIS 替代。"""
    out = {"ok": False, "source": None, "registrar": None, "created": None,
           "expires": None, "status": [], "nameservers": [], "error": None}
    for base in ("https://rdap.org/domain/", "https://rdap.verisign.com/com/v1/domain/"):
        try:
            r = http_get(base + domain, timeout=10)
            if r["status"] != 200:
                out["error"] = "HTTP %s @ %s" % (r["status"], base)
                continue
            j = json.loads(r["text"])
            out["ok"] = True
            out["source"] = base
            for ev in j.get("events", []):
                if ev.get("eventAction") == "registration":
                    out["created"] = ev.get("eventDate")
                if ev.get("eventAction") == "expiration":
                    out["expires"] = ev.get("eventDate")
            out["status"] = j.get("status", [])
            ns = []
            for n in j.get("nameservers", []):
                if isinstance(n, dict):
                    ns.append(n.get("ldhName"))
            out["nameservers"] = [x for x in ns if x][:6]
            for ent in j.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    for item in ent.get("entities", []):
                        for v in item.get("vcardArray", [[], []])[1]:
                            if v[0] == "fn":
                                out["registrar"] = v[3]
                    if not out["registrar"] and ent.get("handle"):
                        out["registrar"] = ent.get("handle")
            out["registrar_id"] = out["registrar"]
            out["registrar"] = IANA_REGISTRAR.get(str(out["registrar"]),
                                                  "IANA#" + str(out["registrar"]))
            return out
        except Exception as e:
            out["error"] = "%s @ %s" % (type(e).__name__, base)
    return out


def ip_profile(ip_or_host):
    target = ip_or_host
    if re.match(r"^[a-zA-Z0-9.\-]+$", target) and not re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        try:
            target = socket.gethostbyname(target)
        except Exception as e:
            return {"input": ip_or_host, "ok": False, "error": "解析失败 " + str(e)[:80]}
    out = {"input": ip_or_host, "ip": target, "ok": False}
    r = http_get("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,"
                 "isp,org,as,query,proxy,hosting,lat,lon,timezone" % target, timeout=10)
    if r["status"] == 200:
        try:
            j = json.loads(r["text"])
            if j.get("status") == "success":
                out.update({"ok": True, "country": j.get("country"),
                            "cc": j.get("countryCode"), "region": j.get("regionName"),
                            "city": j.get("city"), "isp": j.get("isp"), "org": j.get("org"),
                            "as": j.get("as"), "proxy": j.get("proxy"),
                            "hosting": j.get("hosting"), "lat": j.get("lat"),
                            "lon": j.get("lon"), "tz": j.get("timezone")})
                if j.get("proxy") or j.get("hosting"):
                    out["risk"] = "机房/代理出口（VPN、云主机或数据中心）"
                else:
                    out["risk"] = "普通出口"
        except Exception as e:
            out["error"] = "JSON 解析失败 " + str(e)[:60]
    else:
        out["error"] = "ip-api HTTP %s" % r["status"]
    try:
        rd = _nslookup(target, "PTR")
        out["ptr"] = rd["values"][:2]
    except Exception:
        pass
    return out


def domain_profile(domain, do_ip=True):
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    out = {"domain": domain}
    try:
        out["ip"] = socket.gethostbyname(domain)
    except Exception as e:
        out["ip"] = None
        out["resolve_error"] = str(e)[:80]
    out["dns"] = dns_records(domain)
    out["whois"] = rdap_whois(domain)
    if do_ip and out.get("ip"):
        out["ip_info"] = ip_profile(out["ip"])
    # 子域线索：先做泛解析对照，否则 *.github.com 这类会把 shop/blog/admin 全部假命中
    import random
    probe = "zq9x7notreal%d.%s" % (random.randint(1000, 9999), domain)
    try:
        socket.gethostbyname(probe)
        out["wildcard_dns"] = True
    except Exception:
        out["wildcard_dns"] = False
    subs = []
    if not out["wildcard_dns"]:
        for s in ("www", "mail", "api", "admin", "cdn", "m", "shop", "blog"):
            try:
                ip = socket.gethostbyname(s + "." + domain)
                subs.append({"sub": s + "." + domain, "ip": ip})
            except Exception:
                pass
    out["subdomains_alive"] = subs
    return out


# ============================================================================
# CLI
# ============================================================================
def _print_username(rows):
    print("\n%-22s %-10s %-9s %s" % ("站点", "状态", "HTTP", "证据/URL"))
    print("-" * 100)
    for r in rows:
        flag = {"found": "[命中]", "not_found": "[ 无 ]", "unknown": "[ ? ]"}[r["state"]]
        print("%-22s %-10s %-9s %s" % (r["site"][:22], flag, r["status"] or "-",
                                       (r["evidence"] or "")[:46]))
    f = sum(1 for r in rows if r["state"] == "found")
    u = sum(1 for r in rows if r["state"] == "unknown")
    print("-" * 100)
    print("合计 %d 站：命中 %d，未注册 %d，无法判定 %d" % (len(rows), f, len(rows) - f - u, u))


def main():
    ap = argparse.ArgumentParser(description="people.py OSINT 侦察器")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("username"); p.add_argument("user"); p.add_argument("--only", choices=["cn", "intl"])
    p.add_argument("--json", dest="json_out"); p.add_argument("--workers", type=int, default=24)
    p = sub.add_parser("phone"); p.add_argument("number"); p.add_argument("--json", dest="json_out")
    p = sub.add_parser("email"); p.add_argument("addr"); p.add_argument("--json", dest="json_out")
    p = sub.add_parser("domain"); p.add_argument("name"); p.add_argument("--json", dest="json_out")
    p = sub.add_parser("all"); p.add_argument("label")
    p.add_argument("--user"); p.add_argument("--email"); p.add_argument("--phone")
    p.add_argument("--domain"); p.add_argument("--json", dest="json_out")
    p.add_argument("--only", choices=["cn", "intl"])

    a = ap.parse_args()
    if not a.cmd:
        ap.print_help(); return

    def dump(obj, path):
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            print("\n[+] JSON 已写入 %s" % path)

    if a.cmd == "username":
        print("[*] 枚举用户名 %r（并发 %d）…" % (a.user, a.workers))
        rows = enum_username(a.user, region=a.only, workers=a.workers)
        _print_username(rows)
        dump(rows, a.json_out)

    elif a.cmd == "phone":
        r = phone_profile(a.number)
        print("\n手机号画像：%s" % r["input"])
        for k in ("e164", "country", "carrier", "region", "card_type", "risk_level"):
            print("  %-10s %s" % (k, r.get(k)))
        print("  风险项：")
        for x in r["risk"] or ["（无）"]:
            print("    - %s" % x)
        print("  数据来源：%s" % ", ".join(r["source"]) or "内置库")
        dump(r, a.json_out)

    elif a.cmd == "email":
        r = email_profile(a.addr)
        print("\n邮箱画像：%s" % r["email"])
        for k in ("kind", "domain", "local", "risk_level"):
            print("  %-10s %s" % (k, r.get(k)))
        print("  Gravatar：%s（HTTP %s）" % (r["gravatar"]["exists"], r["gravatar"]["http"]))
        print("  MX：%s" % (r["dns"].get("MX") or "无"))
        print("  SPF：%s" % (r["dns"].get("spf") or "无"))
        print("  注册痕迹：")
        for x in r["registrations"]:
            print("    - %-20s %-10s %s" % (x["site"], x["state"], x["evidence"]))
        for x in r["risk"] or []:
            print("  风险：%s" % x)
        dump(r, a.json_out)

    elif a.cmd == "domain":
        r = domain_profile(a.name)
        print("\n域名画像：%s" % r["domain"])
        print("  A 记录     %s" % (r["dns"].get("A") or "无"))
        print("  MX         %s" % (r["dns"].get("MX") or "无"))
        print("  NS         %s" % (r["dns"].get("NS") or "无"))
        print("  SPF        %s" % (r["dns"].get("spf") or "无"))
        print("  DMARC      %s" % (r["dns"].get("dmarc") or "无"))
        w = r["whois"]
        print("  WHOIS(RDAP) ok=%s 注册商=%s 创建=%s 到期=%s" % (
            w["ok"], w["registrar"], w["created"], w["expires"]))
        if w.get("error"):
            print("             err=%s" % w["error"][:70])
        ipi = r.get("ip_info") or {}
        if ipi.get("ok"):
            print("  IP         %s | %s %s %s | ISP=%s | %s" % (
                ipi["ip"], ipi.get("country"), ipi.get("region"), ipi.get("city"),
                ipi.get("isp"), ipi.get("risk")))
        print("  存活子域   %s" % ([s["sub"] for s in r["subdomains_alive"]] or "无"))
        dump(r, a.json_out)

    elif a.cmd == "all":
        bundle = {"label": a.label, "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        if a.user:
            print("[*] 用户名枚举 %r …" % a.user)
            rows = enum_username(a.user, region=a.only)
            _print_username(rows)
            bundle["username"] = rows
        if a.phone:
            bundle["phone"] = phone_profile(a.phone)
            print("\n[*] 手机号：%s / %s / %s" % (bundle["phone"]["country"],
                  bundle["phone"]["carrier"], bundle["phone"]["risk_level"]))
        if a.email:
            bundle["email"] = email_profile(a.email)
            print("[*] 邮箱：%s，Gravatar=%s" % (bundle["email"]["kind"],
                  bundle["email"]["gravatar"]["exists"]))
        if a.domain:
            bundle["domain"] = domain_profile(a.domain)
            print("[*] 域名：A=%s" % (bundle["domain"]["dns"].get("A") or "无"))
        dump(bundle, a.json_out or "osint_result.json")


if __name__ == "__main__":
    main()
