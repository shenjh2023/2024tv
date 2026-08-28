#!/usr/bin/env python3
"""
ziyuanzu.com 资源站监测脚本
功能：
1. 通过 ziyuanzu.com API 获取资源站数据
2. 检测各资源站可用性（HTTP 状态码 + 响应时间）
3. 生成静态 HTML 页面
4. 保存 JSON 数据供历史对比
"""

import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urljoin

import requests

try:
    from pypinyin import lazy_pinyin
    HAS_PINYIN = True
except ImportError:
    HAS_PINYIN = False


def generate_slug(name: str) -> str:
    """将资源站名称转换为 URL slug（拼音）"""
    if not HAS_PINYIN:
        return None
    parts = []
    for char in name:
        if '\u4e00' <= char <= '\u9fff':
            parts.extend(lazy_pinyin(char))
        else:
            parts.append(char)
    return ''.join(parts).lower()


# 使用 ziyuanzu.com API 获取数据（而非 HTML 抓取）
API_BASE = "https://www.ziyuanzu.com/api/v1"
BASE_URL = "https://www.ziyuanzu.com"
TIMEOUT = 15
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Referer": "https://www.google.com/",
}


def fetch_resources_from_api() -> list[dict]:
    """获取资源站列表：优先读取本地 sources.json（避免 GitHub Actions IP 被 Cloudflare 403）"""
    # 1. 优先读取本地静态数据文件
    local_file = os.path.join(os.path.dirname(__file__), "docs", "data", "sources.json")
    if os.path.exists(local_file):
        try:
            with open(local_file, "r", encoding="utf-8") as f:
                resources = json.load(f)
            if resources:
                print(f"[INFO] 从本地 sources.json 加载 {len(resources)} 个资源站")
                return resources
        except Exception as e:
            print(f"[ERROR] 读取本地 sources.json 失败: {e}")

    # 2. 尝试通过 API 获取（本地开发环境可用）
    try:
        resp = requests.get(f"{API_BASE}/sources", params={"limit": 100}, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        print(f"[INFO] API 返回: success={data.get('success')}, 数据量={len(data.get('data', []))}")
        if data.get("success"):
            return data.get("data", [])
    except Exception as e:
        print(f"[ERROR] API 请求失败: {e}")

    # 3. 备选：尝试直接抓取首页 HTML 解析
    print("[WARN] API 不可用，回退到 HTML 抓取...")
    return fetch_resources_from_html()


def fetch_resources_from_html() -> list[dict]:
    """备选方案：从首页 HTML 解析资源站列表"""
    from bs4 import BeautifulSoup

    try:
        resp = requests.get(BASE_URL, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] 首页抓取失败: {e}")
        return []

    soup = BeautifulSoup(resp.text, "lxml")
    resources = []

    # 查找资源站卡片
    cards = soup.find_all("div", class_=re.compile(r"resource-card|source-card|card"))
    if not cards:
        cards = soup.find_all("div", class_=lambda x: x and "resource" in x.lower())

    for card in cards:
        try:
            name_tag = card.find(["h3", "h4", "h5", "a"], class_=re.compile(r"title|name"))
            if not name_tag:
                name_tag = card.find("a")
            name = name_tag.get_text(strip=True) if name_tag else "未知"

            link = ""
            if name_tag and name_tag.has_attr("href"):
                link = urljoin(BASE_URL, name_tag["href"])

            desc_tag = card.find("p", class_=re.compile(r"desc|description"))
            if not desc_tag:
                desc_tag = card.find("p")
            description = desc_tag.get_text(strip=True) if desc_tag else ""

            resources.append({
                "name": name,
                "link": link,
                "description": description,
                "status": "未知",
                "uptime": "-",
                "resource_count": "-",
            })
        except Exception:
            continue

    return resources


def check_site_health(url: str) -> dict:
    """检测单个资源站的健康状态"""
    result = {
        "url": url,
        "status_code": None,
        "response_time_ms": None,
        "is_alive": False,
        "error": None,
    }
    try:
        start = time.time()
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        elapsed = (time.time() - start) * 1000
        result["status_code"] = resp.status_code
        result["response_time_ms"] = round(elapsed, 2)
        # 403/401 视为在线（服务器有响应，只是拒绝了请求，可能是 WAF/Cloudflare 拦截）
        result["is_alive"] = resp.status_code < 400 or resp.status_code in (401, 403)
        if resp.status_code in (401, 403):
            result["error"] = f"HTTP {resp.status_code} (在线但受限)"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection Error"
    except Exception as e:
        result["error"] = str(e)

    return result


def generate_html(data: dict, output_path: str):
    """生成静态 HTML 页面"""
    now = data["timestamp"]
    resources = data["resources"]
    stats = data["stats"]

    total = len(resources)
    alive = sum(1 for r in resources if r.get("health", {}).get("is_alive", False))
    dead = total - alive

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>资源站监测 - www.ziyuanzu.com 资源站实时监控</title>
<meta name="description" content="www.ziyuanzu.com 资源站实时监测面板，共监测{total}个资源站，在线{alive}个，离线{dead}个。更新时间：{now}">
<meta name="keywords" content="资源组, ziyuanzu, 影视资源站, 采集站监测, 资源站监控, 播放源检测">
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --ink: #f1f5f9; --muted: #94a3b8; --accent: #38bdf8; --accent2: #818cf8;
    --success: #4ade80; --danger: #f87171; --warning: #fbbf24;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans SC", sans-serif; background: var(--bg); color: var(--ink); line-height: 1.6; min-height: 100vh; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }}
  header {{ text-align: center; padding: 2rem 1rem; border-bottom: 1px solid var(--surface2); margin-bottom: 2rem; }}
  header h1 {{ font-size: 2rem; font-weight: 800; color: var(--accent); margin-bottom: 0.5rem; }}
  header .subtitle {{ color: var(--muted); font-size: 1rem; }}
  header .update-time {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.5rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: var(--surface); border-radius: 12px; padding: 1.5rem; text-align: center; border: 1px solid var(--surface2); transition: transform 0.2s; }}
  .stat-card:hover {{ transform: translateY(-4px); }}
  .stat-card .number {{ font-size: 2rem; font-weight: 800; }}
  .stat-card .label {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }}
  .stat-card.total .number {{ color: var(--accent); }}
  .stat-card.online .number {{ color: var(--success); }}
  .stat-card.offline .number {{ color: var(--danger); }}
  .stat-card.rate .number {{ color: var(--warning); }}
  .section-title {{ font-size: 1.3rem; font-weight: 700; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--accent); }}
  .resource-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; background: var(--surface); border-radius: 12px; overflow: hidden; }}
  .resource-table thead {{ background: var(--surface2); }}
  .resource-table th, .resource-table td {{ padding: 0.85rem 1rem; text-align: left; }}
  .resource-table th {{ font-weight: 600; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .resource-table tbody tr {{ border-bottom: 1px solid var(--surface2); transition: background 0.15s; }}
  .resource-table tbody tr:hover {{ background: rgba(56,189,248,0.05); }}
  .resource-table tbody tr:last-child {{ border-bottom: none; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .badge-online {{ background: rgba(74,222,128,0.15); color: var(--success); }}
  .badge-offline {{ background: rgba(248,113,113,0.15); color: var(--danger); }}
  .badge-unknown {{ background: rgba(251,191,36,0.15); color: var(--warning); }}
  .resource-name {{ font-weight: 600; color: var(--accent); text-decoration: none; }}
  .resource-name:hover {{ text-decoration: underline; }}
  .resource-desc {{ color: var(--muted); font-size: 0.8rem; }}
  .response-fast {{ color: var(--success); }}
  .response-slow {{ color: var(--warning); }}
  .response-timeout {{ color: var(--danger); }}
  .footer {{ text-align: center; padding: 2rem; color: var(--muted); font-size: 0.85rem; border-top: 1px solid var(--surface2); margin-top: 3rem; }}
  .footer a {{ color: var(--accent); text-decoration: none; }}
  @media (max-width: 768px) {{ .resource-table {{ font-size: 0.8rem; }} .resource-table th, .resource-table td {{ padding: 0.6rem 0.5rem; }} .resource-desc {{ display: none; }} header h1 {{ font-size: 1.5rem; }} }}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>资源站监测</h1>
  <p class="subtitle"><a href="https://www.ziyuanzu.com/" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;border-bottom:1px dotted;">www.ziyuanzu.com</a> 资源站实时监控面板</p>
  <p class="update-time">更新时间：{now}</p>
</header>
<div class="stats-grid">
  <div class="stat-card total"><div class="number">{total}</div><div class="label">监测资源站</div></div>
  <div class="stat-card online"><div class="number">{alive}</div><div class="label">在线站点</div></div>
  <div class="stat-card offline"><div class="number">{dead}</div><div class="label">离线站点</div></div>
  <div class="stat-card rate"><div class="number">{round(alive/total*100,1) if total else 0}%</div><div class="label">在线率</div></div>
</div>
<h2 class="section-title">资源站状态列表</h2>
<table class="resource-table">
  <thead><tr><th>#</th><th>资源站名称</th><th>描述</th><th>状态</th><th>HTTP状态</th><th>响应时间</th><th>可用率</th></tr></thead>
  <tbody>
"""

    for idx, r in enumerate(resources, 1):
        health = r.get("health", {})
        is_alive = health.get("is_alive", False)
        status_code = health.get("status_code", "-")
        resp_time = health.get("response_time_ms")
        error = health.get("error")

        if is_alive:
            badge = '<span class="badge badge-online">在线</span>'
            resp_class = "response-fast" if resp_time and resp_time < 1000 else "response-slow"
            resp_text = f'{resp_time}ms' if resp_time else '-'
        elif error:
            badge = '<span class="badge badge-offline">离线</span>'
            resp_class = "response-timeout"
            resp_text = error
        else:
            badge = '<span class="badge badge-unknown">未知</span>'
            resp_class = "response-timeout"
            resp_text = '-'

        html += f"""
    <tr>
      <td>{idx}</td>
      <td><a class="resource-name" href="{r.get('source_url', r.get('link', '#'))}" target="_blank" rel="noopener">{r.get('name', '未知')}</a></td>
      <td class="resource-desc">{r.get('description', '')}</td>
      <td>{badge}</td>
      <td>{status_code}</td>
      <td class="{resp_class}">{resp_text}</td>
      <td>{r.get('uptime', '-')}</td>
    </tr>
"""

    html += f"""
  </tbody>
</table>
<div class="footer">
  <p>数据来源：<a href="https://www.ziyuanzu.com/" target="_blank" rel="noopener">www.ziyuanzu.com</a> | 监测脚本自动运行</p>
  <p style="margin-top:0.5rem;">本项目为第三方监测工具，与 www.ziyuanzu.com 官方无关</p>
</div>
</div>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[INFO] HTML generated: {output_path}")


def save_json(data: dict, output_path: str):
    """保存 JSON 数据"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[INFO] JSON saved: {output_path}")


def main():
    print("=" * 50)
    print("ziyuanzu.com 资源站监测脚本")
    print("=" * 50)

    # 1. 通过 API 获取资源站列表
    print("\n[1/4] 通过 API 获取资源站数据...")
    api_resources = fetch_resources_from_api()
    print(f"[INFO] 获取到 {len(api_resources)} 个资源站")

    # 去重：同名资源站保留在线的（status=ok 或 uptime 更高）
    seen = {}
    for r in api_resources:
        name = r.get("name", "未知")
        if name not in seen:
            seen[name] = r
        else:
            existing = seen[name]
            # 优先保留 status=ok 的
            if r.get("status") == "ok" and existing.get("status") != "ok":
                seen[name] = r
            # 都 ok 则保留 uptime 更高的
            elif r.get("status") == existing.get("status"):
                if r.get("uptime", 0) > existing.get("uptime", 0):
                    seen[name] = r
    api_resources = list(seen.values())
    print(f"[INFO] 去重后 {len(api_resources)} 个资源站")

    # 2. 转换为统一格式
    resources = []
    for r in api_resources:
        name = r.get("name", "未知")
        slug = generate_slug(name)
        source_url = f"{BASE_URL}/source/{slug}" if slug else r.get("url", "")
        resources.append({
            "name": name,
            "link": r.get("url", ""),
            "source_url": source_url,
            "api": r.get("api", ""),
            "description": r.get("description", ""),
            "status": r.get("status", "未知"),
            "uptime": f"{r.get('uptime', '-')}%" if r.get("uptime") else "-",
            "resource_count": r.get("totalResources", "-"),
            "rating": r.get("rating", "-"),
            "tags": r.get("tags", []),
            "speed": r.get("speed", "-"),
            "responseTime": r.get("responseTime", "-"),
            "todayUpdates": r.get("todayUpdates", 0),
            "_source_status": r.get("status", ""),
            "_source_uptime": r.get("uptime", 0),
        })

    # 3. 并发检测每个资源站的健康状态
    print("[2/4] 并发检测资源站健康状态...")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check_one(idx_r):
        idx, r = idx_r
        link = r.get("link", "")
        source_status = r.get("_source_status", "")
        if link:
            health = check_site_health(link)
            # ziyuanzu 状态优先：ziyuanzu 说在线 → 一定在线（UptimeRobot 多地域检测更可靠）
            if source_status == "ok":
                if not health.get("is_alive"):
                    health["is_alive"] = True
                    health["error"] = f"在线（ziyuanzu 确认，本地检测: {health.get('error') or health.get('status_code')}）"
            # ziyuanzu 说离线，但我们检测在线 → 站点已恢复，ziyuanzu 尚未更新
            elif source_status == "down":
                if health.get("is_alive"):
                    health["error"] = f"在线（本地检测恢复，ziyuanzu 仍显示 down）"
                else:
                    health["is_alive"] = False
            r["health"] = health
            return idx, r, health
        else:
            r["health"] = {"is_alive": False, "error": "No URL"}
            return idx, r, r["health"]

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_one, (i, r)): i for i, r in enumerate(resources)}
        for future in as_completed(futures):
            idx, r, health = future.result()
            status = "在线" if health.get("is_alive") else "离线"
            print(f"  [{idx+1}/{len(resources)}] {r.get('name', '未知')}: {status} ({health.get('status_code') or health.get('error')})")

    # 4. 清理内部字段
    for r in resources:
        r.pop("_source_status", None)
        r.pop("_source_uptime", None)

    # 5. 生成数据
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alive_count = sum(1 for r in resources if r.get("health", {}).get("is_alive", False))
    resp_times = [r["health"]["response_time_ms"] for r in resources
                  if r.get("health", {}).get("response_time_ms")]

    data = {
        "timestamp": timestamp,
        "source": BASE_URL,
        "resources": resources,
        "stats": {
            "total": len(resources),
            "alive": alive_count,
            "offline": len(resources) - alive_count,
            "online_rate": round(alive_count / len(resources) * 100, 1) if resources else 0,
            "avg_response_time": round(sum(resp_times) / len(resp_times), 1) if resp_times else 0,
            "min_response_time": min(resp_times) if resp_times else 0,
            "max_response_time": max(resp_times) if resp_times else 0,
        },
    }

    # 5. 生成全部静态文件
    print("\n[3/4] 生成静态 JSON + HTML 文件...")
    generate_html(data, "docs/index.html")
    save_json(data, f"docs/data/monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    save_json(data, "docs/data/latest.json")

    # 生成分类 JSON（供 AI Agent / MCP 直接 fetch）
    online_list = [r for r in resources if r.get("health", {}).get("is_alive", False)]
    offline_list = [r for r in resources if not r.get("health", {}).get("is_alive", False)]

    save_json({
        "timestamp": timestamp,
        "total": len(online_list),
        "data": online_list,
    }, "docs/data/online.json")

    save_json({
        "timestamp": timestamp,
        "total": len(offline_list),
        "data": offline_list,
    }, "docs/data/offline.json")

    # 统计数据
    ratings = [r.get("rating", 0) for r in resources if isinstance(r.get("rating"), (int, float))]
    speed_dist = {}
    for r in resources:
        s = r.get("speed", "unknown")
        speed_dist[s] = speed_dist.get(s, 0) + 1

    save_json({
        "timestamp": timestamp,
        "overview": {
            "total": len(resources),
            "alive": alive_count,
            "offline": len(resources) - alive_count,
            "onlineRate": round(alive_count / len(resources) * 100, 1) if resources else 0,
        },
        "responseTime": {
            "avg": round(sum(resp_times) / len(resp_times), 1) if resp_times else 0,
            "min": min(resp_times) if resp_times else 0,
            "max": max(resp_times) if resp_times else 0,
            "median": sorted(resp_times)[len(resp_times) // 2] if resp_times else 0,
        },
        "ratingDistribution": {
            "4.5-5.0": sum(1 for r in ratings if r >= 4.5),
            "4.0-4.5": sum(1 for r in ratings if 4.0 <= r < 4.5),
            "3.5-4.0": sum(1 for r in ratings if 3.5 <= r < 4.0),
            "3.0-3.5": sum(1 for r in ratings if 3.0 <= r < 3.5),
            "below-3.0": sum(1 for r in ratings if r < 3.0),
        },
        "speedDistribution": speed_dist,
    }, "docs/data/stats.json")

    # 最快资源站
    fastest = sorted(
        [r for r in online_list if r.get("health", {}).get("response_time_ms")],
        key=lambda r: r["health"]["response_time_ms"],
    )[:20]
    save_json({
        "timestamp": timestamp,
        "total": len(fastest),
        "data": fastest,
    }, "docs/data/fastest.json")

    # 高评分资源站
    top_rated = sorted(
        [r for r in resources if isinstance(r.get("rating"), (int, float)) and r.get("rating", 0) > 0],
        key=lambda r: r.get("rating", 0),
        reverse=True,
    )[:20]
    save_json({
        "timestamp": timestamp,
        "total": len(top_rated),
        "data": top_rated,
    }, "docs/data/top-rated.json")

    print("\n[4/4] 完成！")
    print("=" * 50)
    print(f"监测完成: {len(resources)} 个资源站, {alive_count} 在线, {len(resources) - alive_count} 离线")
    print(f"静态文件:")
    print(f"  docs/index.html       - 监控面板")
    print(f"  data/latest.json      - 全部数据")
    print(f"  data/online.json      - 在线资源站 ({len(online_list)})")
    print(f"  data/offline.json     - 离线资源站 ({len(offline_list)})")
    print(f"  data/stats.json       - 统计数据")
    print(f"  data/fastest.json     - 最快资源站 (Top {len(fastest)})")
    print(f"  data/top-rated.json   - 高评分资源站 (Top {len(top_rated)})")
    print("=" * 50)


if __name__ == "__main__":
    main()
