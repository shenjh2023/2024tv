# -*- coding: utf-8 -*-
"""
无损云影视 Python Spider — 兼容 FongMi/TV (T3) 与 WebHomeTV / PeekPro (T4)
来源: 油猴脚本「全网VIP视频免费解析去广告」的无损云直连通道移植
搜索: https://wsyzy.cc/index.php/ajax/suggest (API 端 wd 搜索已被上游屏蔽)
列表/详情: https://api.wsyzy.net/api.php/provide/vod/ (苹果CMS V10 采集接口)
分类结构: 精选/电影/电视剧/综艺/动漫/4K电影/短剧/纪录片 + 类型/排序筛选
注意: 上游父级分类(电影1/电视剧2/综艺3/动漫4)查询为空，顶级分类直接用叶子 id；
      year/area/lang 筛选参数上游不生效，不提供对应筛选。
"""

import sys
import json
import re
import time
from urllib.parse import quote

sys.path.append('..')

# ===== 兼容导入 =====
try:
    from base.spider import Spider
except ImportError:
    try:
        import requests as _rq
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass
        _session = _rq.Session()
        _session.verify = False
        _session.headers.update({"Connection": "keep-alive"})

        class Spider:
            def fetch(self, url, headers=None, **kw):
                timeout = kw.pop('timeout', 15)
                r = _session.get(url, headers=headers, timeout=timeout, **kw)
                r.encoding = 'utf-8'
                return r
    except ImportError:
        import urllib.request as _ur, ssl as _ssl

        class _FakeResp:
            def __init__(self, data):
                self.text = data.decode('utf-8', 'ignore')
                self.content = data

        class Spider:
            def fetch(self, url, headers=None, **kw):
                timeout = kw.pop('timeout', 15)
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                req = _ur.Request(url, headers=headers or {})
                return _FakeResp(_ur.urlopen(req, timeout=timeout, context=ctx).read())

# ============================================================
# 常量
# ============================================================

SITE = "https://wsyzy.cc"                       # 搜索（suggest）站点
HOST = "https://api.wsyzy.net"                   # 采集 API
API  = HOST + "/api.php/provide/vod/"
UA   = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Mobile Safari/537.36")

ROUTE_ALIAS = {
    "wsym3u8":     "无损云m3u8",
    "wsydownload": "无损云下载",
    "http":        "下载线路",
}

# ── 顶级分类 ──────────────────────────────────────────────────────────────
# 说明: 上游父级分类 t=1/2/3/4 查询返回空(total=0)，内容全在叶子分类，
#       故顶级分类直接指向有量的叶子 id；"featured" 特殊处理：不过滤类型
#       "电影"默认走剧情片(11, 26260条，实际是电影总库)；"电视剧"默认国产剧(13)
CLASSES = [
    {"type_id": "featured", "type_name": "精选"},
    {"type_id": "11",       "type_name": "电影"},
    {"type_id": "13",       "type_name": "电视剧"},
    {"type_id": "25",       "type_name": "综艺"},
    {"type_id": "29",       "type_name": "动漫"},
    {"type_id": "62",       "type_name": "4K电影"},
    {"type_id": "64",       "type_name": "短剧"},
    {"type_id": "20",       "type_name": "纪录片"},
]

# ── 各维度筛选 ────────────────────────────────────────────────────────────

_BY = {
    "key": "by", "name": "排序",
    "value": [
        {"n": "最新", "v": "time"},
        {"n": "人气", "v": "hits"},
        {"n": "评分", "v": "score"},
    ]
}

_TYPE_MOVIE = {
    "key": "t", "name": "类型",
    "value": [
        {"n": "全部",       "v": ""},
        {"n": "4K电影", "v": "62"}, {"n": "动作片", "v": "6"},
        {"n": "喜剧片", "v": "7"},  {"n": "爱情片", "v": "8"},
        {"n": "科幻片", "v": "9"},  {"n": "恐怖片", "v": "10"},
        {"n": "战争片", "v": "12"}, {"n": "邵氏电影", "v": "70"},
        {"n": "Netflix电影", "v": "71"},
    ]
}
_TYPE_TV = {
    "key": "t", "name": "类型",
    "value": [
        {"n": "全部",       "v": ""},
        {"n": "欧美剧", "v": "14"}, {"n": "韩剧",   "v": "15"},
        {"n": "日剧",   "v": "16"}, {"n": "港剧",   "v": "17"},
        {"n": "台剧",   "v": "18"}, {"n": "泰剧",   "v": "19"},
        {"n": "海外剧", "v": "23"}, {"n": "Netflix自制剧", "v": "72"},
    ]
}
_TYPE_SHOW = {
    "key": "t", "name": "类型",
    "value": [
        {"n": "全部",     "v": ""},
        {"n": "日韩综艺", "v": "26"}, {"n": "港台综艺", "v": "27"},
        {"n": "欧美综艺", "v": "28"}, {"n": "演唱会",   "v": "47"},
    ]
}
_TYPE_ANIME = {
    "key": "t", "name": "类型",
    "value": [
        {"n": "全部",     "v": ""},
        {"n": "日韩动漫", "v": "30"}, {"n": "欧美动漫", "v": "31"},
        {"n": "动画片",   "v": "39"}, {"n": "有声动漫", "v": "63"},
    ]
}
_TYPE_DUANJU = {
    "key": "t", "name": "类型",
    "value": [
        {"n": "全部",     "v": ""},
        {"n": "反转爽剧", "v": "65"}, {"n": "古装仙侠", "v": "66"},
        {"n": "年代穿越", "v": "67"}, {"n": "脑洞悬疑", "v": "68"},
        {"n": "现代都市", "v": "69"}, {"n": "漫剧",     "v": "76"},
        {"n": "爽文短剧", "v": "54"},
    ]
}

# 注: 上游 API 的 year/area/lang 参数实测不生效，故不提供年份/地区筛选
FILTERS = {
    "featured": [_BY],
    "11": [_TYPE_MOVIE,  _BY],           # 电影（默认剧情片总库）
    "13": [_TYPE_TV,     _BY],           # 电视剧（默认国产剧）
    "25": [_TYPE_SHOW,   _BY],           # 综艺（默认大陆综艺）
    "29": [_TYPE_ANIME,  _BY],           # 动漫（默认国产动漫）
    "62": [_BY],                         # 4K电影
    "64": [_TYPE_DUANJU, _BY],           # 短剧（默认女频恋爱）
    "20": [_BY],                         # 纪录片
}

# ============================================================
# TTL 缓存
# ============================================================

class _TtlCache:
    def __init__(self):
        self._store = {}

    def get(self, key):
        item = self._store.get(key)
        if item and time.time() - item[1] < item[2]:
            return item[0]
        return None

    def set(self, key, value, ttl):
        self._store[key] = (value, time.time(), ttl)

_cache = _TtlCache()

# ============================================================
# Spider 主类
# ============================================================

class Spider(Spider):

    def __init__(self):
        self._home_cache       = []
        self._home_cache_time = 0
        self.extend = ""
        self.header = {"User-Agent": UA, "Referer": SITE + "/"}

    def getName(self):
        return "无损云影视"

    def init(self, extend=""):
        # 兼容字符串/字典/列表形式的 extend
        self.extend = "" if isinstance(extend, list) else (extend or "")

    # ─── 网络工具 ────────────────────────────────────────────────────

    def _rsp_text(self, rsp):
        if rsp is None: return ""
        if isinstance(rsp, str):
            t = rsp.lstrip("\ufeff").strip()
            return t
        if isinstance(rsp, bytes):
            return rsp.decode('utf-8', 'ignore').lstrip("\ufeff").strip()
        try:
            t = rsp.text
        except Exception:
            try:
                t = rsp.content.decode('utf-8', 'ignore')
            except Exception:
                return ""
        return (t or "").lstrip("\ufeff").strip()

    def _fetch(self, url, timeout=12, headers=None):
        """统一请求入口：部分 T3 环境的 fetch 不接受 timeout，自动降级"""
        h = headers or self.header
        try:
            return self.fetch(url, headers=h, timeout=timeout)
        except TypeError:
            return self.fetch(url, headers=h)
        except Exception:
            # 偶发失败重试一次
            try:
                return self.fetch(url, headers=h, timeout=timeout)
            except TypeError:
                return self.fetch(url, headers=h)

    def _get_json(self, url, timeout=15, headers=None, retries=3):
        for i in range(retries + 1):
            try:
                text = self._rsp_text(self._fetch(url, timeout=timeout, headers=headers))
                if text:
                    return json.loads(text)
            except TypeError:
                # fetch 签名不兼容已由 _fetch 处理，此处不重试同样错误
                break
            except Exception:
                if i >= retries:
                    return None
                time.sleep(0.6)
        return None

    # ─── 辅助 ────────────────────────────────────────────────────────

    @staticmethod
    def _norm_pic(pic):
        pic = (pic or "").strip()
        if not pic: return ""
        return ("https:" + pic) if pic.startswith("//") else pic

    @staticmethod
    def _alias_routes(from_str):
        parts = from_str.split("$$$") if from_str else []
        return "$$$".join(ROUTE_ALIAS.get(p.strip(), p.strip()) for p in parts)

    def _item_to_card(self, item):
        return {
            "vod_id":      str(item.get("vod_id", item.get("id", ""))),
            "vod_name":    item.get("vod_name", item.get("name", "未知")),
            "vod_pic":     self._norm_pic(item.get("vod_pic", "")),
            "vod_remarks": item.get("vod_remarks", ""),
        }

    def _build_detail(self, item):
        content = re.sub(r'<[^>]+>', '',
                         item.get("vod_content") or item.get("vod_blurb") or "").strip()
        all_froms = (item.get("vod_play_from", "") or "").split("$$$") if item.get("vod_play_from") else []
        all_urls  = (item.get("vod_play_url",  "") or "").split("$$$")  if item.get("vod_play_url")  else []
        down_from = item.get("vod_down_from", "")
        down_url  = item.get("vod_down_url", "")
        if down_url and down_url.strip():
            all_froms.append(down_from or "http")
            all_urls.append(down_url)

        return {
            "vod_id":        str(item.get("vod_id", "")),
            "vod_name":      item.get("vod_name",    "未知"),
            "vod_pic":       self._norm_pic(item.get("vod_pic", "")),
            "type_name":     item.get("type_name",   ""),
            "vod_year":      str(item.get("vod_year", "")),
            "vod_area":      item.get("vod_area",    ""),
            "vod_remarks":   item.get("vod_remarks", ""),
            "vod_actor":     item.get("vod_actor",    ""),
            "vod_director":  item.get("vod_director", ""),
            "vod_content":   content,
            "vod_play_from": self._alias_routes("$$$".join(all_froms)),
            "vod_play_url":  "$$$".join(all_urls),
        }

    # ============================================================
    # 首页
    # ============================================================

    def homeContent(self, filter):
        return {"class": CLASSES, "filters": FILTERS}

    def homeVideoContent(self):
        now = int(time.time())
        if self._home_cache and now - self._home_cache_time < 300:
            return {"list": self._home_cache}
        data = self._get_json(API + "?ac=videolist&pg=1&by=time")
        if not data or not data.get("list"):
            return {"list": []}
        cards = [self._item_to_card(i) for i in data["list"]]
        self._home_cache       = cards
        self._home_cache_time = now
        return {"list": cards}

    # ============================================================
    # 分类列表（类型/年份/排序筛选）
    # ============================================================

    def categoryContent(self, tid, pg, filter, extend):
        try:
            page = max(1, int(pg or 1))
            ext = {}
            if extend:
                if isinstance(extend, dict):
                    ext = extend
                elif isinstance(extend, str):
                    try:
                        ext = json.loads(extend) if extend.strip() else {}
                    except Exception:
                        ext = {}

            by   = ext.get("by", "time")
            sub_t = ext.get("t", "")

            if tid == "featured":
                url = API + "?ac=videolist&pg=%d&by=%s" % (page, by or "time")
            else:
                eff_tid = sub_t if sub_t else tid
                url = API + "?ac=videolist&t=%s&pg=%d" % (eff_tid, page)
                if by:   url += "&by=" + by

            cached = _cache.get("cat_" + url)
            if cached: return cached

            data = self._get_json(url)
            if not data or not data.get("list"):
                return {"page": page, "pagecount": 1, "limit": 20, "total": 0, "list": []}

            result = {
                "list":      [self._item_to_card(i) for i in data.get("list", [])],
                "page":      page,
                "pagecount": int(data.get("pagecount", 1)),
                "limit":     20,
                "total":     int(data.get("total", 0)),
            }
            _cache.set("cat_" + url, result, ttl=180)
            return result
        except Exception:
            return {"page": 1, "pagecount": 1, "limit": 20, "total": 0, "list": []}

    # ============================================================
    # 详情
    # ============================================================

    def detailContent(self, ids):
        try:
            if isinstance(ids, str): ids = [ids]
            vod_id = str(ids[0])
            cached = _cache.get("det_" + vod_id)
            if cached: return cached

            data = self._get_json(API + "?ac=detail&ids=" + vod_id)
            if not data or not data.get("list"):
                return {"list": []}

            vod = self._build_detail(data["list"][0])
            if not vod.get("vod_play_url"):
                return {"list": []}

            result = {"list": [vod]}
            _cache.set("det_" + vod_id, result, ttl=300)
            return result
        except Exception:
            return {"list": []}

    # ============================================================
    # 搜索（API 端 wd 已被上游屏蔽，走站点 suggest 接口，再批量补详情）
    # ============================================================

    def searchContent(self, key, quick, pg="1"):
        try:
            key = (key or "").strip()
            if not key: return {"list": []}
            page = max(1, int(pg or 1))
            url = SITE + "/index.php/ajax/suggest?mid=1&wd=%s&pg=%d" % (
                quote(key, safe=''), page)
            data = self._get_json(url, timeout=10)
            if not data or not data.get("list"):
                return {"list": []}

            items = data["list"]
            cards = []
            # suggest 只给 id/name，批量拉详情补齐图片与集数信息
            id_list = [str(it.get("id", "")) for it in items if it.get("id")][:20]
            detail_map = {}
            if id_list:
                d = self._get_json(API + "?ac=detail&ids=" + ",".join(id_list), timeout=12)
                if d and d.get("list"):
                    for it in d["list"]:
                        detail_map[str(it.get("vod_id"))] = it
            for it in items:
                vid = str(it.get("id", ""))
                src = detail_map.get(vid)
                if src:
                    cards.append(self._item_to_card(src))
                else:
                    cards.append({
                        "vod_id":      vid,
                        "vod_name":    it.get("name", "未知"),
                        "vod_pic":     self._norm_pic(it.get("pic", "")),
                        "vod_remarks": it.get("remarks", ""),
                    })
            return {"list": cards}
        except Exception:
            return {"list": []}

    # ============================================================
    # 播放解析
    # ============================================================

    def playerContent(self, flag, id, vipFlags):
        if not id:
            return {"parse": 0, "playUrl": "", "url": ""}
        play_url  = str(id).replace("\\/", "/")
        url_lower = play_url.lower()
        is_m3u8   = ".m3u8" in url_lower
        is_media  = is_m3u8 or ".mp4" in url_lower or ".flv" in url_lower
        if is_media:
            return {
                "parse":       0,
                "playUrl":     "",
                "url":         play_url,
                "header":      {"User-Agent": UA, "Referer": SITE + "/"},
                "format":      "application/x-mpegURL" if is_m3u8 else "",
                "contentType": "application/x-mpegURL" if is_m3u8 else "",
            }
        return {
            "parse": 1,
            "playUrl": "",
            "url":    play_url,
            "header": {"User-Agent": UA, "Referer": SITE + "/"},
        }

    def localProxy(self, param):
        return [200, "text/plain", b"ok", {}]

    def destroy(self): pass
    def close(self):   self.destroy()
