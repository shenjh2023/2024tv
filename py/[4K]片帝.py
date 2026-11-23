# -*- coding: utf-8 -*-
"""
@header({
  searchable: 1,
  filterable: 1,
  quickSearch: 1,
  title: 'mock',
  lang: 'hipy',
})
dongpian1.com TVBox Spider
- 签名: HMAC-SHA256, KEY 从 movie-card-runtime-DSGpZH3f.js 提取
- 详情页真实线路名，4K 排第一
- 官方/4K 直连，普通线路白名单过滤 + HLS 代理清洗
"""
import re
import json
import hmac
import hashlib
import time
import secrets
import uuid
import threading
import requests
from urllib.parse import quote, unquote, urljoin, urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

try:
    from base.spider import Spider as BaseSpider
    RUN_IN_TVBOX = True
except ImportError:
    RUN_IN_TVBOX = False
    class BaseSpider:
        def init(self, extend=""): pass
        def getName(self): return "mock"


# ==================== HLS 清洗 ====================
def clean_m3u8(text, ad_keywords, min_duration=0.5):
    try:
        lines = text.splitlines()
        if not lines or lines[0].strip() != "#EXTM3U":
            return text
        if "#EXT-X-MAP:" in text:
            return text

        header_lines, segments = [], []
        cur = {"tags": [], "uri": "", "dur": 0.0}
        in_seg = False
        orig_seq = 0
        has_endlist = False

        for line in lines:
            s = line.strip()
            if not s:
                continue
            if s.startswith("#EXTINF:"):
                in_seg = True
                m = re.search(r"#EXTINF:([0-9.]+)", s)
                cur["dur"] = float(m.group(1)) if m else 3.0
                cur["tags"].append(line)
            elif s.startswith("#EXT-X-MEDIA-SEQUENCE:"):
                m = re.search(r"#EXT-X-MEDIA-SEQUENCE:(\d+)", s)
                if m:
                    orig_seq = int(m.group(1))
            elif s == "#EXT-X-ENDLIST":
                has_endlist = True
            elif s.startswith("#"):
                if in_seg:
                    cur["tags"].append(line)
                else:
                    header_lines.append(line)
            else:
                if in_seg:
                    cur["uri"] = s
                    segments.append(cur)
                    cur = {"tags": [], "uri": "", "dur": 0.0}
                    in_seg = False
                else:
                    header_lines.append(line)

        if not segments:
            return text

        cleaned, removed = [], 0
        for seg in segments:
            uri_low = seg["uri"].lower()
            is_ad = any(k in uri_low for k in ad_keywords)
            if 0 < seg["dur"] < min_duration:
                is_ad = True
            if is_ad:
                removed += 1
                continue
            cleaned.extend(seg["tags"])
            cleaned.append(seg["uri"])

        seg_count = sum(1 for x in cleaned if not x.strip().startswith("#"))
        if seg_count < 3:
            return text

        out = ["#EXTM3U"]
        out.extend(l for l in header_lines if not l.strip().startswith("#EXTM3U"))
        if removed > 0:
            out.append(f"#EXT-X-MEDIA-SEQUENCE:{orig_seq + removed}")
        out.extend(cleaned)
        if has_endlist:
            out.append("#EXT-X-ENDLIST")
        return "\n".join(out)
    except Exception:
        return text


def absolutize_m3u8(text, base_url, proxy_port=0):
    try:
        p = urlparse(base_url)
        base_dir = p.path.rsplit("/", 1)[0] + "/"
        base = f"{p.scheme}://{p.netloc}{base_dir}"
        out = []
        for line in text.splitlines():
            s = line.strip()
            if not s:
                out.append(line)
                continue
            if s.startswith("#EXT-X-KEY:") or s.startswith("#EXT-X-MAP:"):
                def repl(m):
                    uri = m.group(1)
                    abs_uri = uri if uri.startswith("http") else urljoin(base, uri)
                    if proxy_port > 0:
                        return f'URI="http://127.0.0.1:{proxy_port}/?url={quote(abs_uri, safe="")}"'
                    return f'URI="{abs_uri}"'
                out.append(re.sub(r'URI="([^"]+)"', repl, s))
            elif s.startswith("#"):
                out.append(line)
            else:
                out.append(urljoin(base, s))
        return "\n".join(out)
    except Exception:
        return text


# ==================== HLS 代理 ====================
class HLSProxyServer:
    _server = None
    _port = 0
    _lock = threading.Lock()
    _session = None
    _session_lock = threading.Lock()
    _cache = {}
    _cache_lock = threading.Lock()
    _cache_ttl = 8

    class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    @classmethod
    def _get_session(cls, ua, referer):
        if cls._session is None:
            with cls._session_lock:
                if cls._session is None:
                    s = requests.Session()
                    s.headers.update({
                        "User-Agent": ua,
                        "Accept": "*/*",
                        **({"Referer": referer} if referer else {}),
                    })
                    cls._session = s
        return cls._session

    @classmethod
    def _fetch(cls, url, ua, referer):
        with cls._cache_lock:
            hit = cls._cache.get(url)
            if hit and time.time() - hit[0] < cls._cache_ttl:
                return hit[1]
        try:
            r = cls._get_session(ua, referer).get(url, timeout=6)
            text = r.content.decode("utf-8", "replace")
            with cls._cache_lock:
                cls._cache[url] = (time.time(), text)
                if len(cls._cache) > 100:
                    items = sorted(cls._cache.items(), key=lambda x: x[1][0])
                    for k, _ in items[:50]:
                        cls._cache.pop(k, None)
            return text
        except Exception:
            return None

    @classmethod
    def start(cls, config):
        with cls._lock:
            if cls._server is not None:
                return cls._port
            for port in range(9979, 9999):
                try:
                    handler = cls._make_handler(config)
                    srv = cls._ThreadingHTTPServer(("127.0.0.1", port), handler)
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    cls._server = srv
                    cls._port = port
                    return port
                except OSError:
                    continue
                except Exception:
                    continue
            return 0

    @classmethod
    def stop(cls):
        with cls._lock:
            if cls._server is not None:
                try:
                    cls._server.shutdown()
                except Exception:
                    pass
                cls._server = None
                cls._port = 0

    @classmethod
    def _make_handler(cls, config):
        ad_keywords = config.get("ad_keywords", [])
        min_duration = config.get("min_duration", 0.5)
        default_ua = config.get("ua", "Mozilla/5.0")
        default_ref = config.get("referer", "")

        class Handler(BaseHTTPRequestHandler):
            def _rewrite_master(self, text, base_url):
                port = HLSProxyServer._port
                if port <= 0:
                    return text
                out = []
                for line in text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        out.append(line)
                        continue
                    absolute = urljoin(base_url, s)
                    if ".m3u8" in absolute.lower():
                        out.append(f"http://127.0.0.1:{port}/?url={quote(absolute, safe='')}")
                    else:
                        out.append(absolute)
                return "\n".join(out)

            def _do_fetch(self):
                try:
                    parsed = urlparse(self.path)
                    params = parse_qs(parsed.query)
                    target = params.get("url", [""])[0]
                    if not target:
                        self.send_response(400)
                        self.end_headers()
                        return

                    is_m3u8 = "m3u8" in target.lower()

                    if not is_m3u8:
                        try:
                            r = requests.get(target, headers={
                                "User-Agent": default_ua,
                                "Referer": default_ref,
                            }, timeout=10, stream=True)
                            self.send_response(r.status_code)
                            for k, v in r.headers.items():
                                if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                                    self.send_header(k, v)
                            self.end_headers()
                            for chunk in r.iter_content(8192):
                                self.wfile.write(chunk)
                            return
                        except Exception:
                            self.send_response(502)
                            self.end_headers()
                            return

                    text = HLSProxyServer._fetch(target, default_ua, default_ref)
                    if text is None:
                        self.send_response(302)
                        self.send_header("Location", target)
                        self.end_headers()
                        return

                    if "#EXT-X-STREAM-INF" in text:
                        text = self._rewrite_master(text, target)
                    else:
                        text = clean_m3u8(text, ad_keywords, min_duration)
                        text = absolutize_m3u8(text, target, HLSProxyServer._port)

                    body = text.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/vnd.apple.mpegurl")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "max-age=6")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                except Exception:
                    try:
                        self.send_response(302)
                        self.send_header("Location", target)
                        self.end_headers()
                    except Exception:
                        pass

            def do_GET(self):
                self._do_fetch()

            def do_HEAD(self):
                self._do_fetch()

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "*")
                self.end_headers()

            def log_message(self, *args):
                pass

        return Handler


# ==================== Spider ====================
class Spider(BaseSpider):
    host = "https://dongpian1.com"
    SIGN_KEY = "8b9a908a05eac640e1ee06f52acaa741bfe4ba9e004eeffdbeb635e532e06666"
    PAGE_SIZE = 20

    ENABLE_HLS_CLEAN = True

    # ★ 普通线路白名单：只保留以下 7 条
    # 支持 provider_id 和中文 label 两种匹配
    PLAIN_WHITELIST_IDS = {
        "yyzy1080",   # 1080zyk
        "mdzy",       # 魔都资源
        "ikun",       # ikun资源
        "wsyzy",      # 无水印资源
        "zuida",      # 最大资源
        "liangzi",    # 量子资源
        "niuniu",     # 牛牛资源
    }
    PLAIN_WHITELIST_NAMES = {
        "1080zyk", "魔都资源", "ikun资源", "无水印资源",
        "最大资源", "量子资源", "牛牛资源",
    }

    KIND_MAP = {
        "movie": "movie", "series": "series",
        "anime": "anime", "variety": "variety", "short": "short",
    }

    PLAY_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
        "Origin": "https://dongpian1.com",
        "Referer": "https://dongpian1.com/",
    }

    def init(self, extend=""):
        self.proxy_config = {
            "ad_keywords": [
                "advert", "preroll", "片头", "广告",
                "/gg/", "banner", "promo", "casino", "博彩",
                "充值", "sponsor", "/ad/", "/ads/", "ad.mp4", "ad.m3u8",
            ],
            "min_duration": 0.5,
            "ua": self.PLAY_HEADERS["User-Agent"],
            "referer": self.PLAY_HEADERS["Referer"],
        }

    def destroy(self):
        try:
            HLSProxyServer.stop()
        except Exception:
            pass

    # ========== 签名 ==========
    def _sign(self, method, api, search_or_data=""):
        ts = str(int(time.time() * 1000))
        n = secrets.token_hex(16)
        msg = f"{method.upper()}\n{api}{search_or_data}\n{ts}\n{n}"
        sig = hmac.new(self.SIGN_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
        return {
            "x-ai-movie-timestamp": ts,
            "x-ai-movie-nonce": n,
            "x-ai-movie-signature": sig,
        }

    def _get_json(self, path, params=None, tag=""):
        query_string = ""
        if params:
            query_string = "?" + "&".join(f"{k}={v}" for k, v in params.items())
        headers = self._sign("GET", path, query_string)
        url = self.host + path + query_string
        try:
            r = requests.get(url, headers=headers, timeout=15)
        except Exception as e:
            print(f"[{tag}] GET {path} -> EXC {e}")
            return None
        if r.status_code != 200:
            print(f"[{tag}] GET {path} -> {r.status_code}: {r.text[:150]}")
            return None
        try:
            return r.json()
        except Exception:
            print(f"[{tag}] GET {path} -> 非 JSON")
            return None

    def _post_json(self, path, query_string, body_dict, tag=""):
        body_str = json.dumps(body_dict, ensure_ascii=False, separators=(",", ":"))
        headers = self._sign("POST", path, query_string)
        headers["Content-Type"] = "application/json"
        url = self.host + path + query_string
        try:
            r = requests.post(url, headers=headers,
                              data=body_str.encode("utf-8"), timeout=15)
        except Exception as e:
            print(f"[{tag}] POST {path} -> EXC {e}")
            return None
        if r.status_code not in (200, 201):
            print(f"[{tag}] POST {path} -> {r.status_code}: {r.text[:150]}")
            return None
        try:
            return r.json()
        except Exception:
            return None

    # ========== 筛选 ==========
    @staticmethod
    def _sort_options():
        return [
            {"n": "热度", "v": "trending"},
            {"n": "最近更新", "v": "new"},
            {"n": "评分", "v": "score"},
            {"n": "上映时间", "v": "time"},
        ]

    @staticmethod
    def _window_options():
        return [
            {"n": "日榜", "v": "day"},
            {"n": "周榜", "v": "week"},
            {"n": "月榜", "v": "month"},
            {"n": "全部", "v": "all"},
        ]

    def _build_filter_objects(self, tid):
        return [
            {"key": "sort", "name": "排序", "value": self._sort_options()},
            {"key": "window", "name": "榜单", "value": self._window_options()},
        ]

    def _build_filters_dict(self, tid):
        return {
            "sort": self._sort_options(),
            "window": self._window_options(),
        }

    # ========== 首页 ==========
    def homeContent(self, filter=False):
        classes = [
            {"type_id": "movie", "type_name": "电影"},
            {"type_id": "series", "type_name": "电视剧"},
            {"type_id": "anime", "type_name": "动漫"},
            {"type_id": "variety", "type_name": "综艺"},
            {"type_id": "short", "type_name": "短剧"},
        ]
        filters = {c["type_id"]: self._build_filter_objects(c["type_id"]) for c in classes}
        return {"class": classes, "filters": filters}

    def homeVideoContent(self):
        data = self._get_json("/v1/feed/home", {
            "scope": "public", "mode": "preview",
            "sections": 3, "cards": 10,
        }, tag="homeVideoContent")
        if not data:
            return {"list": []}
        videos = []
        for sec in data.get("sections", []):
            for card in sec.get("cards", []):
                videos.append(self._card_to_vod(card))
        return {"list": videos[:50]}

    # ========== 分类 ==========
    def categoryContent(self, tid="movie", pg="1", filter=False, extend=None):
        kind = self.KIND_MAP.get(str(tid), "movie")
        try:
            pg_num = int(pg or 1)
        except Exception:
            pg_num = 1
        ext = self._safe_dict(extend)

        sort = str(ext.get("sort") or "trending")
        window = str(ext.get("window") or "day")

        data = self._get_json("/v1/browse/catalog", {
            "sort": sort, "window": window,
            "page": pg_num, "limit": 20, "kind": kind,
        }, tag="categoryContent")
        if not data:
            return {"list": [], "page": pg_num, "pagecount": 1,
                    "limit": 20, "total": 0,
                    "filters": self._build_filters_dict(tid)}

        videos = [self._card_to_vod(c) for c in data.get("cards", [])]
        pagination = data.get("pagination") or {}
        has_more = pagination.get("has_more", False)
        pagecount = min(pg_num + 1, 999) if has_more else pg_num

        return {
            "list": videos, "page": pg_num, "pagecount": pagecount,
            "limit": 20, "total": pagecount * 20,
            "filters": self._build_filters_dict(tid),
        }

    # ========== 搜索 ==========
    def searchContent(self, key="", quick=False, pg="1"):
        if not key:
            return {"list": []}

        thread_body = {
            "title": key,
            "metadata": {
                "search_fields": "all",
                "search_scope_label": "综合",
                "search_mode": "fast",
                "source": "movie_composer_route",
                "submission_id": str(uuid.uuid4()),
            }
        }
        thread = self._post_json("/v1/threads", "", thread_body,
                                 tag="searchContent/thread")
        thread_id = (thread or {}).get("id", "")
        if not thread_id:
            return {"list": []}

        time.sleep(1.5)

        try:
            pg_num = int(pg or 1)
        except Exception:
            pg_num = 1
        data = self._get_json("/v1/browse/catalog", {
            "page": pg_num, "limit": 20,
            "query_mode": "fast_v3",
            "thread_id": thread_id,
            "search_fields": "all",
            "q": quote(key),
        }, tag="searchContent/query")
        if not data:
            return {"list": []}

        raw = data.get("cards") or data.get("results") or data.get("items") or []
        videos = [self._card_to_vod(c) for c in raw]
        return {"list": videos, "page": pg_num}

    # ========== 详情：白名单过滤普通线路，4K 排第一 ==========
    def detailContent(self, ids=None):
        ids = self._safe_list(ids)
        if not ids:
            return {"list": []}
        vod_id = str(ids[0])

        data = self._get_json(f"/v1/catalog/{vod_id}", tag="detailContent")
        if not data:
            return {"list": []}

        episodes = data.get("episodes") or []
        if not episodes:
            return {"list": []}

        first_token = episodes[0].get("token", "")
        lines = []
        if first_token:
            resolve_data = self._get_json(
                f"/v1/playback/resolve/{first_token}",
                tag="detailContent/resolve",
            )
            if resolve_data:
                lines = resolve_data.get("line_options") or []

        # ★ 白名单过滤：官方/4K 全留，普通线路只留指定的 7 条
        filtered = []
        for opt in lines:
            kind = opt.get("url_kind") or ""
            label = opt.get("label") or opt.get("provider_name") or ""
            pid = opt.get("provider_id") or ""

            # 官方/4K（resolve_ticket 或名称带官方/4K）→ 全保留
            if kind == "resolve_ticket" or "官方" in label or "4K" in label or "4k" in label:
                filtered.append(opt)
                continue

            # 普通线路（m3u8 直链）→ 检查白名单
            if kind == "m3u8" or opt.get("url", "").startswith("http"):
                if pid in self.PLAIN_WHITELIST_IDS or label in self.PLAIN_WHITELIST_NAMES:
                    filtered.append(opt)

        lines = filtered

        # 排序：4K → 官方 → 普通（按 preference_weight 降序）
        def _priority(opt):
            label = opt.get("label") or opt.get("provider_name") or ""
            is_4k = "4K" in label or "4k" in label
            is_official = opt.get("url_kind") == "resolve_ticket"
            weight = -(opt.get("preference_weight") or 0)
            if is_4k:
                return (0, weight)
            if is_official:
                return (1, weight)
            return (2, weight)

        lines.sort(key=_priority)

        play_from_list = []
        play_url_list = []
        for opt in lines:
            line_id = opt.get("playback_source_id") or opt.get("id") or ""
            if not line_id:
                continue
            name = opt.get("label") or opt.get("provider_name") or line_id
            play_from_list.append(name)

            ep_strs = []
            for ep in episodes:
                ep_num = ep.get("number", 0)
                ep_title = ep.get("title") or f"第{ep_num}集"
                ep_strs.append(f"{ep_title}${vod_id}|{line_id}|{ep_num}")
            play_url_list.append("#".join(ep_strs))

        if not play_from_list:
            ep_strs = []
            for ep in episodes:
                ep_num = ep.get("number", 0)
                ep_title = ep.get("title") or f"第{ep_num}集"
                ep_strs.append(f"{ep_title}${vod_id}||{ep_num}")
            play_from_list = ["默认线路"]
            play_url_list = ["#".join(ep_strs)]

        return {"list": [{
            "vod_id": vod_id,
            "vod_name": data.get("title") or "",
            "vod_pic": data.get("poster_url") or "",
            "vod_content": data.get("description") or "",
            "vod_year": str(data.get("year") or ""),
            "vod_actor": "、".join(data.get("actors") or []),
            "vod_director": "、".join(data.get("directors") or []),
            "vod_play_from": "$$$".join(play_from_list),
            "vod_play_url": "$$$".join(play_url_list),
        }]}

    # ========== 播放 ==========
    def playerContent(self, flag="", id="", vipFlags=None):
        id = str(id or "")
        if id.startswith("http") and (".m3u8" in id or ".mp4" in id):
            return {"parse": 0, "url": id, "header": self.PLAY_HEADERS}

        parts = id.split("|")
        if len(parts) != 3:
            return {"parse": 1, "url": "", "msg": "id 格式错误"}
        vod_id, line_id, ep_num = parts

        detail = self._get_json(f"/v1/catalog/{vod_id}", tag="playerContent/detail")
        if not detail:
            return {"parse": 1, "url": "", "msg": "详情加载失败"}
        target_token = None
        for ep in detail.get("episodes") or []:
            if str(ep.get("number")) == str(ep_num):
                target_token = ep.get("token")
                break
        if not target_token:
            return {"parse": 1, "url": "", "msg": f"找不到第{ep_num}集"}

        resolve = self._get_json(f"/v1/playback/resolve/{target_token}",
                                 tag="playerContent/resolve")
        if not resolve:
            return {"parse": 1, "url": "", "msg": "resolve 失败"}
        lines = resolve.get("line_options") or []

        target_line = None
        for opt in lines:
            oid = opt.get("playback_source_id") or opt.get("id") or ""
            if oid == line_id:
                target_line = opt
                break
        if not target_line:
            for opt in lines:
                name = opt.get("label") or opt.get("provider_name") or ""
                if name == line_id:
                    target_line = opt
                    break
        if not target_line:
            return {"parse": 1, "url": "", "msg": f"线路 {line_id} 不存在"}

        url = target_line.get("url") or ""
        kind = target_line.get("url_kind") or ""
        label = target_line.get("label") or ""

        # 官方/4K：resolve_ticket → 换 m3u8，直连
        if kind == "resolve_ticket" or url.startswith("resolve://"):
            ticket = url.replace("resolve://", "")
            line_data = self._post_json(
                "/v1/playback/resolve-line", "?view=compact",
                {"ticket": ticket}, tag=f"line/{label}",
            )
            play_url = ((line_data or {}).get("line") or {}).get("url", "")
            if play_url:
                return {"parse": 0, "url": play_url, "header": self.PLAY_HEADERS}
            return {"parse": 1, "url": "", "msg": f"「{label}」解析失败"}

        # 普通：m3u8 直链，走 HLS 代理清洗
        if kind == "m3u8" or (url.startswith("http") and ".m3u8" in url):
            if self.ENABLE_HLS_CLEAN:
                port = HLSProxyServer.start(self.proxy_config)
                if port > 0:
                    proxy_url = f"http://127.0.0.1:{port}/?url={quote(url, safe='')}"
                    return {"parse": 0, "url": proxy_url, "header": self.PLAY_HEADERS}
            return {"parse": 0, "url": url, "header": self.PLAY_HEADERS}

        return {"parse": 1, "url": "", "msg": "线路类型不支持"}

    # ========== 辅助 ==========
    def _card_to_vod(self, card):
        return {
            "vod_id": str(card.get("id") or ""),
            "vod_name": card.get("title") or "",
            "vod_pic": card.get("poster_url") or "",
            "vod_remarks": card.get("remarks") or "",
        }

    @staticmethod
    def _safe_list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, (str, int)):
            return [str(v)]
        return []

    @staticmethod
    def _safe_dict(v):
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return {}
            try:
                d = json.loads(s)
                return d if isinstance(d, dict) else {}
            except Exception:
                return {}
        return {}


# ==================== 测试入口 ====================
if __name__ == "__main__":
    spider = Spider()
    spider.init()
    try:
        home = spider.homeVideoContent().get("list", [])
        print("0. homeVideoContent:", len(home))

        hc = spider.homeContent(True)
        print("1. filters dict:", isinstance(hc.get("filters"), dict))

        if home:
            vid = home[0]["vod_id"]
            res = spider.detailContent([vid])
            lst = res.get("list", [])
            print("2. detailContent:", len(lst), "条")
            if lst:
                play_from = lst[0].get("vod_play_from") or ""
                lines = play_from.split("$$$")
                print(f"   线路数: {len(lines)}")
                for i, name in enumerate(lines):
                    print(f"     [{i}] {name}")

                play_url = lst[0].get("vod_play_url", "")
                groups = play_url.split("$$$")
                print(f"\n3. 测试前 2 条线路播放")
                for i in range(min(2, len(lines))):
                    if i >= len(groups) or not groups[i]:
                        continue
                    first_ep = groups[i].split("#")[0]
                    ep_id = first_ep.split("$")[1]
                    play_res = spider.playerContent("", ep_id)
                    is_proxy = str(play_res.get("url", "")).startswith("http://127.0.0.1")
                    print(f"   [{lines[i]}] parse={play_res.get('parse')} "
                          f"proxy={is_proxy} url={str(play_res.get('url'))[:70]}")
    finally:
        spider.destroy()
