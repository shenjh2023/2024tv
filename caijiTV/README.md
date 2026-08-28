# ziyuanzhan - 资源站监测

ziyuanzu.com 资源站实时监测面板。通过 [ziyuanzu API](https://www.ziyuanzu.com/api/v1) 获取资源站数据，定期检测各站点可用性，生成静态 JSON + HTML 页面。

## 工作原理

```
GitHub Actions (每6小时) → monitor.py → fetch ziyuanzu API → 健康检查 → 生成静态文件 → GitHub Pages 自动部署
```

**零服务器、零运行时、零成本。**

## 静态文件

部署到 GitHub Pages 后，可通过以下 URL 访问：

| 文件 | URL | 说明 |
|------|-----|------|
| `docs/index.html` | `https://mylazily.github.io/ziyuanzhan/` | 可视化监控面板 |
| `data/latest.json` | `https://mylazily.github.io/ziyuanzhan/data/latest.json` | 全部资源站数据 |
| `data/online.json` | `https://mylazily.github.io/ziyuanzhan/data/online.json` | 在线资源站 |
| `data/offline.json` | `https://mylazily.github.io/ziyuanzhan/data/offline.json` | 离线资源站 |
| `data/stats.json` | `https://mylazily.github.io/ziyuanzhan/data/stats.json` | 统计数据 |
| `data/fastest.json` | `https://mylazily.github.io/ziyuanzhan/data/fastest.json` | 响应最快 Top 20 |
| `data/top-rated.json` | `https://mylazily.github.io/ziyuanzhan/data/top-rated.json` | 高评分 Top 20 |

## AI Agent 使用示例

```python
import requests

# 获取所有在线资源站
resp = requests.get("https://mylazily.github.io/ziyuanzhan/data/online.json")
data = resp.json()
print(f"在线资源站: {data['total']} 个")
for r in data["data"][:5]:
    print(f"  {r['name']} - {r['link']}")

# 获取统计数据
stats = requests.get("https://mylazily.github.io/ziyuanzhan/data/stats.json").json()
print(f"在线率: {stats['overview']['onlineRate']}%")
```

## 本地运行

```bash
pip install requests beautifulsoup4 lxml
python monitor.py
```

生成的文件：
- `docs/index.html` — 监控面板
- `docs/data/*.json` — 各类 JSON 数据

## 项目结构

```
ziyuanzhan/
├── monitor.py               # 监测脚本（核心）
├── requirements.txt         # Python 依赖
├── .github/workflows/
│   └── monitor.yml          # GitHub Actions 定时监控 + 部署
└── docs/                    # GitHub Pages 根目录
    ├── index.html           # 静态监控面板
    └── data/
        ├── latest.json      # 全部数据
        ├── online.json      # 在线资源站
        ├── offline.json     # 离线资源站
        ├── stats.json       # 统计数据
        ├── fastest.json     # 最快资源站
        ├── top-rated.json   # 高评分资源站
        └── monitor_*.json   # 历史快照
```

## 数据来源

- [ziyuanzu.com](https://www.ziyuanzu.com) API: `https://www.ziyuanzu.com/api/v1/sources`
- 本项目为第三方监测工具，与 ziyuanzu.com 官方无关
