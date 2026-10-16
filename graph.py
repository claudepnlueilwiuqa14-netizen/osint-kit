#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
graph.py —— 关系图谱引擎（把「人 - 用户名 - 邮箱 - 域名 - 社交账号 - IP」串成一张图）

数据源全部来自 people.py 的真实结果（people.py 的 --json 输出），本模块不做任何二次猜测：
    - people.py username --json u.json   -> 账号节点（found 的才建边）
    - people.py email    --json e.json   -> 邮箱节点 + 域名节点
    - people.py phone    --json p.json   -> 号码节点
    - people.py domain   --json d.json   -> 域名/IP/NS/子域节点
也可用 --bundle 直接吃 people.py all --json 出来的合并包。

产出：
    1) graph.json    节点/边结构化数据
    2) graph.html    自包含 D3/vis 风格力导向图（纯 SVG + JS，离线可开，中文标注）
    3) 控制台打印邻接表与"桥接标识"（同一个邮箱/域名/号码串起多个人的关键点）

用法：
    python graph.py --bundle osint_result.json --out graph.json --html graph.html
    python graph.py --username demo_username.json --email demo_email.json --domain demo_domain.json
"""
import os
import re
import sys
import json
import html
import argparse
import urllib.request
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

NODE_STYLE = {
    "person":   {"color": "#ff6b6b", "r": 26, "label": "人物"},
    "account":  {"color": "#4ecdc4", "r": 18, "label": "社交账号"},
    "email":    {"color": "#ffd93d", "r": 20, "label": "邮箱"},
    "domain":   {"color": "#6c5ce7", "r": 22, "label": "域名"},
    "phone":    {"color": "#00b894", "r": 20, "label": "号码"},
    "ip":       {"color": "#fd79a8", "r": 18, "label": "IP"},
    "ns":       {"color": "#a29bfe", "r": 14, "label": "DNS服务器"},
    "subdomain": {"color": "#b2bec3", "r": 13, "label": "子域"},
}

EDGE_STYLE = {
    "has_account": "注册/使用",
    "has_email": "邮箱",
    "has_phone": "号码",
    "owns_domain": "持有域名",
    "email_at": "邮箱属于域名",
    "domain_ip": "解析到",
    "domain_ns": "权威DNS",
    "domain_sub": "子域",
    "ip_asn": "归属",
}


class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, nid, ntype, label, **props):
        if nid in self.nodes:
            self.nodes[nid]["props"].update(props)
            return self.nodes[nid]
        self.nodes[nid] = {"id": nid, "type": ntype, "label": label, "props": props}
        return self.nodes[nid]

    def add_edge(self, a, b, rel, weight=1, **props):
        if a not in self.nodes or b not in self.nodes:
            return
        for e in self.edges:
            if e["from"] == a and e["to"] == b and e["rel"] == rel:
                e["weight"] += weight
                return
        self.edges.append({"from": a, "to": b, "rel": rel,
                           "label": EDGE_STYLE.get(rel, rel), "weight": weight,
                           **props})

    # ---------------- 装载各类 people.py 结果 ----------------
    def load_username(self, data, person=None, min_state=("found",)):
        rows = data if isinstance(data, list) else data.get("username", [])
        user = None
        for r in rows:
            if r.get("state") not in min_state:
                continue
            site = r["site"]
            nid = "acct:%s:%s" % (site, r["url"].split("/")[-1] or site)
            self.add_node(nid, "account", "%s" % site,
                          url=r.get("url"), evidence=r.get("evidence"),
                          http=r.get("status"))
            if person:
                self.add_edge(person, nid, "has_account")
        return len([r for r in rows if r.get("state") in min_state])

    def load_email(self, data, person=None):
        if isinstance(data, list):
            data = data[0] if data else {}
        addr = data.get("email")
        if not addr:
            return 0
        self.add_node("email:" + addr, "email", addr, kind=data.get("kind"),
                      gravatar=(data.get("gravatar") or {}).get("exists"),
                      risk=data.get("risk_level"))
        if person:
            self.add_edge(person, "email:" + addr, "has_email")
        dom = data.get("domain")
        if dom:
            self.add_node("domain:" + dom, "domain", dom)
            self.add_edge("email:" + addr, "domain:" + dom, "email_at")
        for reg in data.get("registrations", []):
            if reg.get("state") == "found":
                nid = "acct:%s(email)" % reg["site"]
                self.add_node(nid, "account", reg["site"],
                              evidence=reg.get("evidence"))
                self.add_edge("email:" + addr, nid, "has_account")
        return 1

    def load_phone(self, data, person=None):
        if isinstance(data, list):
            data = data[0] if data else {}
        d = data.get("digits")
        if not d:
            return 0
        nid = "phone:" + d
        self.add_node(nid, "phone", data.get("e164") or d,
                      carrier=data.get("carrier"), country=data.get("country"),
                      card_type=data.get("card_type"), risk=data.get("risk_level"))
        if person:
            self.add_edge(person, nid, "has_phone")
        return 1

    def load_domain(self, data, person=None):
        if isinstance(data, list):
            data = data[0] if data else {}
        dom = data.get("domain")
        if not dom:
            return 0
        dn = "domain:" + dom
        w = data.get("whois") or {}
        self.add_node(dn, "domain", dom, registrar=w.get("registrar"),
                      created=w.get("created"), expires=w.get("expires"),
                      wildcard=data.get("wildcard_dns"))
        if person:
            self.add_edge(person, dn, "owns_domain")
        for ip in (data.get("dns") or {}).get("A", [])[:4]:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                ipn = "ip:" + ip
                self.add_node(ipn, "ip", ip)
                self.add_edge(dn, ipn, "domain_ip")
                ipi = data.get("ip_info") or {}
                if ipi.get("ok"):
                    self.nodes[ipn]["props"].update(
                        {"country": ipi.get("country"), "isp": ipi.get("isp"),
                         "as": ipi.get("as"), "risk": ipi.get("risk")})
        for ns in (data.get("dns") or {}).get("NS", [])[:4]:
            nsn = "ns:" + ns
            self.add_node(nsn, "ns", ns)
            self.add_edge(dn, nsn, "domain_ns")
        for s in data.get("subdomains_alive", []):
            sn = "subdomain:" + s["sub"]
            self.add_node(sn, "subdomain", s["sub"], ip=s.get("ip"))
            self.add_edge(dn, sn, "domain_sub")
        return 1

    # ---------------- 分析 ----------------
    def bridges(self):
        """桥接标识：度数最高的非人物节点——多个人的交汇点，调查价值最高。"""
        deg = defaultdict(int)
        for e in self.edges:
            deg[e["from"]] += 1
            deg[e["to"]] += 1
        out = []
        for nid, n in self.nodes.items():
            if n["type"] == "person":
                continue
            out.append({"id": nid, "label": n["label"], "type": n["type"],
                        "degree": deg[nid], "props": n["props"]})
        out.sort(key=lambda x: -x["degree"])
        return out[:15]

    def to_dict(self):
        return {"nodes": list(self.nodes.values()), "edges": self.edges,
                "stats": {"nodes": len(self.nodes), "edges": len(self.edges),
                          "by_type": {t: sum(1 for n in self.nodes.values() if n["type"] == t)
                                      for t in NODE_STYLE}}}


# ---------------- HTML 可视化（自包含，离线可开）----------------
def render_html(g, title="OSINT 关系图谱"):
    d = g.to_dict()
    payload = json.dumps(d, ensure_ascii=False)
    legend = "".join(
        '<span class="lg"><i style="background:%s"></i>%s</span>' % (v["color"], v["label"])
        for v in NODE_STYLE.values())
    return """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>%(title)s</title><style>
body{margin:0;background:#0b0d12;color:#e6e9ef;font-family:-apple-system,"Microsoft YaHei",sans-serif}
#hdr{padding:14px 20px;border-bottom:1px solid #232733;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
#hdr h1{font-size:16px;margin:0;font-weight:600}
.lg{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#9aa4b2;margin-right:12px}
.lg i{width:10px;height:10px;border-radius:50%%;display:inline-block}
svg{display:block;background:#0b0d12}
.nlab{font-size:11px;fill:#dfe4ec;pointer-events:none;text-anchor:middle}
.elab{font-size:9px;fill:#7f8a9c}
#tip{position:fixed;background:#161a23;border:1px solid #2c3140;padding:8px 10px;border-radius:6px;
font-size:12px;max-width:320px;display:none;z-index:9;line-height:1.5}
#stat{padding:10px 20px;font-size:12px;color:#8b95a6}
</style></head><body>
<div id="hdr"><h1>%(title)s</h1><div id="lgd">%(legend)s</div></div>
<div id="stat"></div><svg id="cv" width="1200" height="760"></svg><div id="tip"></div>
<script>
const D = %(payload)s;
const ST = %(style)s;
const W=1200,H=760, nodes=D.nodes.map((n,i)=>({...n,x:W/2+Math.cos(i)*260,y:H/2+Math.sin(i)*260,vx:0,vy:0}));
const idx={}; nodes.forEach((n,i)=>idx[n.id]=i);
const edges=D.edges.filter(e=>idx[e.from]!==undefined&&idx[e.to]!==undefined);
document.getElementById('stat').textContent =
  '节点 '+nodes.length+' ｜ 边 '+edges.length+' ｜ 类型分布 '+
  Object.entries(D.stats.by_type).filter(x=>x[1]>0).map(x=>x[0]+':'+x[1]).join(' , ');
const svg=document.getElementById('cv');
const NS='http://www.w3.org/2000/svg';
function el(t,a){const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e;}
const gl=el('g',{}),gn=el('g',{}); svg.appendChild(gl);svg.appendChild(gn);
const eline=edges.map(e=>el('line',{stroke: e.rel==='has_account'?'#3d4757':'#39404f','stroke-width':1.2}));
eline.forEach(l=>gl.appendChild(l));
const etxt=edges.map(e=>el('text',{class:'elab','text-anchor':'middle'}));
const gnode=nodes.map(n=>{
  const st=ST[n.type]||{color:'#888',r:14};
  const g=el('g',{});
  g.appendChild(el('circle',{r:st.r,fill:st.color,'fill-opacity':.82,stroke:'#0b0d12','stroke-width':2}));
  const t=el('text',{class:'nlab',y:st.r+13}); t.textContent=n.label.length>22?n.label.slice(0,20)+'…':n.label;
  g.appendChild(t); gn.appendChild(g); return g;});
const tip=document.getElementById('tip');
nodes.forEach((n,i)=>{const g=gnode[i];
 g.onmousemove=ev=>{tip.style.display='block';tip.style.left=(ev.clientX+12)+'px';tip.style.top=(ev.clientY+12)+'px';
  tip.innerHTML='<b>'+n.label+'</b><br>类型：'+(ST[n.type]?ST[n.type].label:n.type)+
   '<br>'+Object.entries(n.props||{}).filter(x=>x[1]!==null&&x[1]!==''&&x[1]!==undefined)
   .slice(0,6).map(x=>x[0]+'：'+x[1]).join('<br>')};
 g.onmouseout=()=>tip.style.display='none';});
function tick(){
  for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
    let dx=nodes[j].x-nodes[i].x, dy=nodes[j].y-nodes[i].y, d=Math.hypot(dx,dy)||0.01;
    if(d<420){const f=(420-d)*0.0016; nodes[i].vx-=dx/d*f*90; nodes[i].vy-=dy/d*f*90;
      nodes[j].vx+=dx/d*f*90; nodes[j].vy+=dy/d*f*90;}}
  edges.forEach((e,k)=>{const a=nodes[idx[e.from]],b=nodes[idx[e.to]];
    const dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||0.01,f=(d-150)*0.006;
    a.vx+=dx/d*f*60;a.vy+=dy/d*f*60;b.vx-=dx/d*f*60;b.vy-=dy/d*f*60;});
  nodes.forEach(n=>{n.vx*=0.86;n.vy*=0.86;n.x+=n.vx*0.02;n.y+=n.vy*0.02;
    n.x=Math.max(60,Math.min(W-60,n.x));n.y=Math.max(40,Math.min(H-40,n.y));});
  edges.forEach((e,k)=>{const a=nodes[idx[e.from]],b=nodes[idx[e.to]],l=eline[k];
    l.setAttribute('x1',a.x);l.setAttribute('y1',a.y);l.setAttribute('x2',b.x);l.setAttribute('y2',b.y);
    const t=etxt[k]; if(!t.parentNode)gl.appendChild(t);
    t.setAttribute('x',(a.x+b.x)/2);t.setAttribute('y',(a.y+b.y)/2-3);t.textContent=e.label;});
  nodes.forEach((n,i)=>gnode[i].setAttribute('transform','translate('+n.x+','+n.y+')'));
  requestAnimationFrame(tick);}
tick();
</script></body></html>""" % {"title": html.escape(title), "legend": legend,
                               "payload": payload,
                               "style": json.dumps(NODE_STYLE, ensure_ascii=False)}


def main():
    ap = argparse.ArgumentParser(description="graph.py 关系图谱")
    ap.add_argument("--bundle", help="people.py all 输出的合并 JSON")
    ap.add_argument("--username"); ap.add_argument("--email")
    ap.add_argument("--phone"); ap.add_argument("--domain")
    ap.add_argument("--person", default=None, help="人物节点名（默认取 --bundle 的 label）")
    ap.add_argument("--out", default="graph.json")
    ap.add_argument("--html", dest="html_out", default="graph.html")
    ap.add_argument("--title", default="OSINT 关系图谱")
    a = ap.parse_args()

    def jload(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    g = Graph()
    person = a.person
    if a.bundle:
        b = jload(a.bundle)
        person = person or b.get("label") or "目标人物"
        g.add_node("person:" + person, "person", person)
        if b.get("username"):
            g.load_username(b["username"], "person:" + person)
        if b.get("email"):
            g.load_email(b["email"], "person:" + person)
        if b.get("phone"):
            g.load_phone(b["phone"], "person:" + person)
        if b.get("domain"):
            g.load_domain(b["domain"], "person:" + person)
    else:
        person = person or "目标人物"
        g.add_node("person:" + person, "person", person)
        if a.username:
            g.load_username(jload(a.username), "person:" + person)
        if a.email:
            g.load_email(jload(a.email), "person:" + person)
        if a.phone:
            g.load_phone(jload(a.phone), "person:" + person)
        if a.domain:
            g.load_domain(jload(a.domain), "person:" + person)

    d = g.to_dict()
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    with open(a.html_out, "w", encoding="utf-8") as f:
        f.write(render_html(g, a.title))

    print("[+] 图谱：节点 %d，边 %d" % (d["stats"]["nodes"], d["stats"]["edges"]))
    print("    类型分布：%s" % {k: v for k, v in d["stats"]["by_type"].items() if v})
    print("[+] 已写 %s / %s" % (a.out, a.html_out))
    print("\n桥接标识（度数最高，调查价值最大）：")
    for b in g.bridges():
        if b["degree"] == 0:
            continue
        print("  %-4d %-14s %s" % (b["degree"], b["type"], b["label"]))
    print("\n邻接关系（前 25 条）：")
    for e in d["edges"][:25]:
        print("  %-40s --[%s]--> %s" % (e["from"][:40], e["label"], e["to"][:40]))


if __name__ == "__main__":
    main()
