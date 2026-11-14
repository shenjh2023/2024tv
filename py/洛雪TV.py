#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 洛雪TV (tv.lxyy.club) → TVBox/drpy2 采集源
# v3-20261103：普通线路全量展开（站点「网络公开收集」全部采集源，≤8 源节流 1.5 秒、总线路 ≤24，预算内截断保底）
# v2-20261103：接入站点解析线路（默认解析/TXNP/闪电/洛雪聚合）；官采平台线路逐解析接口展开；直链源附「净化」线路
# 站点结构（2026-11-03 实测）：
#   普通影视聚合站（非成人站），PHP 多页 + WebHTV 改版前端，TMDB 对齐片目，多采集源聚合（dytt/qilin/jl/mj/360zy 等）
#   分类列表  GET /api/tmdb.php?path=discover/movie&api_key=server-configured&language=zh-CN&page=N&...
#   采集源搜索 GET /api/proxy.php?action=search&wd={片名}&page=1
#   采集源详情 GET /api/proxy.php?action=detail&source={源}&id={id} → 选集；dytt 等直出 m3u8，qilin 官采直出平台页
#   站点配置  GET /api/proxy.php?action=config → official_routes 解析线路 + sources[].player_api
#   解析线路拼法（实测 detail-player-modal.js buildParserTarget）：api 以 url= 结尾 → api + encodeURIComponent(选集地址)
#   站内 json 型线路（洛雪4K/蓝光，/json-player.php）需浏览器播放会话，纯客户端 403，不接入（README 注明）
# 网络层：节流 2 秒 / 缓存 300 秒 / CC 拦截 180 秒冷却 / 方法 20 秒预算封顶 / homeContent 零网络

import sys
import re
import time
import json
import urllib.request
import urllib.parse

VERSION = "v3-20261103"
HOST = "https://tv.lxyy.club"
IMG_BASE = "https://image.tmdb.org/t/p/w342"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
PLAYER_UA = "okhttp/3.15.0"
TMDB_KEY = "server-configured"
TMDB_LANG = "zh-CN"

METHOD_BUDGET = 20.0
REQ_TIMEOUT = 10
THROTTLE = 1.5
CACHE_TTL = 300
COOLDOWN = 180
MAX_SOURCES = 8
MAX_TOTAL_LINES = 24

_cache = {}
_last_req = [0.0]
_block_until = [0.0]
_cfg_state = [None, 0.0]

# 解析线路兜底（2026-11-03 实测 config 样本，config 拉取失败时使用）
FALLBACK_ROUTES = [
    ("默认解析", "https://svip.qlplayer.cyou/?url="),
    ("TXNP", "https://art.txnp.cn/?url="),
    ("闪电", "https://bfq.txnp.cn/excessive?url="),
    ("洛雪聚合", "https://jx.lxyy.club/index.php?url="),
]
FALLBACK_SOURCE_API = {
    "qilin": "https://svip.qlplayer.cyou/?url=",
    "mj": "https://mujizybf.com/m3u8/?url=",
    "jl": "https://jimaoys99.com/parse?url=",
    "360zy": "https://jimaoys99.com/parse?url=",
    "dytt": "https://jimaoys99.com/parse?url=",
    "ik": "https://jimaoys99.com/parse?url=",
    "md": "https://jimaoys99.com/parse?url=",
    "fy": "https://svip.qlplayer.cyou/?url=",
}
FALLBACK_SOURCE_NAME = {
    "qilin": "官采蓝光", "mj": "4k60帧", "jl": "自营", "360zy": "360资源",
    "dytt": "电影天堂", "ik": "ikun", "md": "魔都", "fy": "官方源",
}

_DIRECT_PATH_RE = re.compile(r"\.(?:m3u8|mp4)$", re.I)


def _log(msg):
    try:
        sys.stderr.write("[lxyy] %s\n" % msg)
    except Exception:
        pass


def _get(url, deadline=None):
    """带节流/缓存/CC冷却的抓取，失败返回 None"""
    now = time.time()
    if now < _block_until[0]:
        return None
    hit = _cache.get(url)
    if hit and now - hit[0] < CACHE_TTL:
        return hit[1]
    if deadline is not None and now >= deadline - 0.5:
        return None
    gap = now - _last_req[0]
    if gap < THROTTLE:
        time.sleep(THROTTLE - gap)
    _last_req[0] = time.time()
    for _ in range(2):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept": "application/json, text/html, */*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
            })
            resp = urllib.request.urlopen(req, timeout=REQ_TIMEOUT)
            data = resp.read().decode("utf-8", "ignore")
            low = data[:4000].lower()
            if resp.status in (403, 412, 503) or "just a moment" in low or "cf-browser-verification" in low:
                _block_until[0] = time.time() + COOLDOWN
                _log("CC block, cooldown %ss" % COOLDOWN)
                return None
            _cache[url] = (time.time(), data)
            return data
        except Exception as e:
            _log("fetch fail %s (%s)" % (url[:120], e))
            if deadline is not None and time.time() >= deadline - 1.0:
                return None
    return None


def _get_json(url, deadline=None):
    data = _get(url, deadline)
    if not data:
        return None
    try:
        obj = json.loads(data)
    except Exception:
        _log("non-json response %s" % url[:120])
        return None
    return obj if isinstance(obj, dict) else None


def _clean(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", str(text))
    text = (text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " "))
    return text.strip()


def _safe(s):
    return (s or "").replace("$", "＄").replace("#", "＃").replace("|", "｜")


def _enc(u):
    return urllib.parse.quote(u or "", safe="")


def _is_direct(u):
    """按 URL 自身路径判断是否直链媒体（解析页地址的 query 里带 m3u8 也不算直链）"""
    try:
        path = urllib.parse.urlsplit(u).path
        return bool(_DIRECT_PATH_RE.search(path))
    except Exception:
        return False


def _today():
    return time.strftime("%Y-%m-%d")


MOVIE_BASE = {"sort_by": "popularity.desc", "include_adult": "false",
              "include_video": "false", "primary_release_date.lte": _today()}
SERIES_BASE = {"sort_by": "popularity.desc", "include_adult": "false",
               "include_null_first_air_dates": "false", "first_air_date.lte": _today()}

# 分类全量（实测自站点 /js/catalog-categories.js 的 CESHI_CATALOG_LISTS，38 个 + TMDB 趋势）
# (type_id, type_name, media, path, extra_params)
CATS = [
    ("movie-all", "电影·全部", "movie", "discover/movie", {}),
    ("movie-popular", "电影·热门", "movie", "discover/movie", {}),
    ("movie-latest", "电影·最新", "movie", "discover/movie", {"sort_by": "primary_release_date.desc"}),
    ("movie-rated", "电影·高分", "movie", "discover/movie", {"sort_by": "vote_average.desc", "vote_count.gte": "200"}),
    ("cn-movie", "电影·国产", "movie", "discover/movie", {"with_original_language": "zh", "with_origin_country": "CN"}),
    ("movie-hktw", "电影·港澳台", "movie", "discover/movie", {"with_origin_country": "HK|TW|MO"}),
    ("movie-western", "电影·欧美", "movie", "discover/movie", {"with_original_language": "en"}),
    ("movie-jpkr", "电影·日韩", "movie", "discover/movie", {"with_origin_country": "JP|KR"}),
    ("movie-action", "电影·动作", "movie", "discover/movie", {"with_genres": "28"}),
    ("movie-comedy", "电影·喜剧", "movie", "discover/movie", {"with_genres": "35"}),
    ("movie-romance", "电影·爱情", "movie", "discover/movie", {"with_genres": "10749"}),
    ("movie-mystery", "电影·悬疑", "movie", "discover/movie", {"with_genres": "9648"}),
    ("movie-scifi", "电影·科幻", "movie", "discover/movie", {"with_genres": "878"}),
    ("movie-horror", "电影·恐怖", "movie", "discover/movie", {"with_genres": "27"}),
    ("movie-animation", "电影·动画", "movie", "discover/movie", {"with_genres": "16"}),
    ("movie-documentary", "电影·纪录片", "movie", "discover/movie", {"with_genres": "99"}),
    ("series-all", "剧集·全部", "tv", "discover/tv", {}),
    ("series-hot", "剧集·热播", "tv", "discover/tv", {}),
    ("series-latest", "剧集·最新", "tv", "discover/tv", {"sort_by": "first_air_date.desc"}),
    ("series-rated", "剧集·高分", "tv", "discover/tv", {"sort_by": "vote_average.desc", "vote_count.gte": "200"}),
    ("cn-tv", "剧集·国产", "tv", "discover/tv", {"with_original_language": "zh", "with_origin_country": "CN", "without_genres": "16"}),
    ("series-korea", "剧集·韩剧", "tv", "discover/tv", {"with_origin_country": "KR"}),
    ("series-japan", "剧集·日剧", "tv", "discover/tv", {"with_origin_country": "JP"}),
    ("series-western", "剧集·欧美", "tv", "discover/tv", {"with_original_language": "en"}),
    ("series-action", "剧集·动作冒险", "tv", "discover/tv", {"with_genres": "10759"}),
    ("series-comedy", "剧集·喜剧", "tv", "discover/tv", {"with_genres": "35"}),
    ("series-mystery", "剧集·悬疑", "tv", "discover/tv", {"with_genres": "9648"}),
    ("series-crime", "剧集·犯罪", "tv", "discover/tv", {"with_genres": "80"}),
    ("series-scifi", "剧集·科幻奇幻", "tv", "discover/tv", {"with_genres": "10765"}),
    ("series-animation", "剧集·动画", "tv", "discover/tv", {"with_genres": "16"}),
    ("series-documentary", "剧集·纪录片", "tv", "discover/tv", {"with_genres": "99"}),
    ("western-animation", "剧集·英文动画", "tv", "discover/tv", {"with_genres": "16", "with_original_language": "en"}),
    ("anime-all", "动漫·全部", "tv", "discover/tv", {"with_genres": "16"}),
    ("anime-cn", "动漫·国漫", "tv", "discover/tv", {"with_genres": "16", "with_original_language": "zh", "with_origin_country": "CN"}),
    ("anime-japan", "动漫·日漫", "tv", "discover/tv", {"with_genres": "16", "with_origin_country": "JP"}),
    ("anime-western", "动漫·欧美", "tv", "discover/tv", {"with_genres": "16", "with_original_language": "en"}),
    ("anime-latest", "动漫·最新", "tv", "discover/tv", {"with_genres": "16", "sort_by": "first_air_date.desc"}),
    ("anime-rated", "动漫·高分", "tv", "discover/tv", {"with_genres": "16", "sort_by": "vote_average.desc", "vote_count.gte": "100"}),
    ("tmdb-trending", "榜单·TMDB趋势", "all", "trending/all/day", {}),
]
CAT_MAP = dict((c[0], c) for c in CATS)


def _tmdb_url(path, params, page):
    q = {"path": path, "api_key": TMDB_KEY, "language": TMDB_LANG, "page": str(page)}
    q.update(params)
    return HOST + "/api/tmdb.php?" + urllib.parse.urlencode(q)


def _search_url(wd, page=1):
    return HOST + "/api/proxy.php?" + urllib.parse.urlencode({"action": "search", "wd": wd, "page": str(page)})


def _detail_url(source, vid):
    return HOST + "/api/proxy.php?" + urllib.parse.urlencode(
        {"action": "detail", "source": str(source), "id": str(vid)})


def _config_url():
    return HOST + "/api/proxy.php?action=config"


def _watch_url(title, media, tmdb_id, pic=""):
    return HOST + "/watch.php?" + urllib.parse.urlencode({
        "title": title, "media": "tmdb:%s:%s" % (media, tmdb_id), "pic": pic or ""})


def _play_url(source, vid, title, pic=""):
    return HOST + "/play.php?" + urllib.parse.urlencode({
        "source": str(source), "id": str(vid), "title": title or "", "pic": pic or ""})


def _parse_query(url):
    try:
        pos = url.find("?")
        qs = urllib.parse.parse_qs(url[pos + 1:] if pos >= 0 else url)
        out = {}
        for k, v in qs.items():
            out[k] = v[0] if v else ""
        return out
    except Exception:
        return {}


def _load_config(deadline):
    """站点配置（解析线路 + 源解析接口），缓存 300 秒；失败返回 None 用内置兜底"""
    if _cfg_state[0] is not None and time.time() - _cfg_state[1] < CACHE_TTL:
        return _cfg_state[0]
    data = _get_json(_config_url(), deadline)
    if data and isinstance(data.get("sources"), dict):
        _cfg_state[0] = data
        _cfg_state[1] = time.time()
        return data
    return None


def _parser_routes(cfg):
    """可用解析线路 [(名称, api)]：iframe 型、非移动端隐藏、未禁用；json 型（需播放会话）排除"""
    routes = []
    for r in (cfg or {}).get("official_routes") or []:
        if not isinstance(r, dict):
            continue
        api = str(r.get("api") or "").strip()
        name = str(r.get("name") or "").strip()
        if not api or not name:
            continue
        if str(r.get("type") or "") == "json":
            continue
        if r.get("hide_mobile") or r.get("player_codes_enabled") or r.get("enabled") is False:
            continue
        if api.startswith("/"):
            api = HOST + api
        routes.append((name, api))
    return routes or list(FALLBACK_ROUTES)


def _source_api(cfg, source):
    if cfg:
        s = (cfg.get("sources") or {}).get(source) or {}
        api = str(s.get("player_api") or "").strip()
        if api:
            return api
    return FALLBACK_SOURCE_API.get(source, "")


def _source_name(cfg, source):
    if cfg:
        s = (cfg.get("sources") or {}).get(source) or {}
        name = str(s.get("name") or "").strip()
        if name:
            return name
    return FALLBACK_SOURCE_NAME.get(source, "")


class Spider(object):

    def init(self, extend=""):
        _log("lxyy %s ready" % VERSION)
        return self

    def getName(self):
        return "洛雪TV"

    def isVideoFormat(self, url):
        return _is_direct(url or "")

    def manualVideoCheck(self, url):
        return not _is_direct(url or "")

    def homeContent(self, filter):
        classes = [{"type_id": c[0], "type_name": c[1]} for c in CATS]
        return {"class": classes, "list": [], "filters": {}}

    def homeVideoContent(self):
        return {"list": []}

    def categoryContent(self, tid, pg, filter, extend):
        deadline = time.time() + METHOD_BUDGET
        cat = CAT_MAP.get(tid)
        if not cat:
            return {"list": [], "page": pg, "pagecount": 0, "limit": "", "total": 0}
        try:
            pg = int(pg)
        except Exception:
            pg = 1
        if pg < 1:
            pg = 1
        _, _, media, path, extra = cat
        params = {}
        if path.startswith("discover/"):
            params = dict(MOVIE_BASE) if media == "movie" else dict(SERIES_BASE)
            params.update(extra)
        else:
            params = dict(extra)
        data = _get_json(_tmdb_url(path, params, pg), deadline)
        vods = []
        if data:
            for it in data.get("results") or []:
                if not isinstance(it, dict):
                    continue
                mt = it.get("media_type") or (media if media in ("movie", "tv") else "")
                if mt not in ("movie", "tv"):
                    continue
                name = it.get("title") or it.get("name") or ""
                tmdb_id = it.get("id")
                if not name or tmdb_id is None:
                    continue
                poster = it.get("poster_path") or ""
                pic = IMG_BASE + poster if poster else ""
                date = str(it.get("release_date") or it.get("first_air_date") or "")
                vote = it.get("vote_average")
                remarks = date[:4] if date else ""
                if isinstance(vote, (int, float)) and vote > 0:
                    remarks = (remarks + " · " if remarks else "") + ("%.1f分" % vote)
                vods.append({
                    "vod_id": _watch_url(name, mt, tmdb_id, pic),
                    "vod_name": name,
                    "vod_pic": pic,
                    "vod_remarks": remarks,
                })
        return {"list": vods, "page": pg,
                "pagecount": data.get("total_pages") or (1 if vods else 0) if data else 0,
                "limit": len(vods), "total": data.get("total_results") or len(vods) if data else 0}

    def searchContent(self, key, quick):
        key = (key or "").strip()
        if not key:
            return {"list": []}
        deadline = time.time() + METHOD_BUDGET
        data = _get_json(_search_url(key, 1), deadline)
        if not data or data.get("need_captcha"):
            _log("search unavailable or captcha required")
            return {"list": []}
        vods = []
        for row in data.get("results") or []:
            if not isinstance(row, dict):
                continue
            source = row.get("source")
            vid = row.get("id")
            name = row.get("name") or ""
            if not source or vid is None or not name:
                continue
            pic = row.get("pic") or ""
            vods.append({
                "vod_id": _play_url(source, vid, name, pic),
                "vod_name": name,
                "vod_pic": pic,
                "vod_remarks": row.get("remarks") or row.get("type") or "",
            })
            if len(vods) >= 30:
                break
        return {"list": vods}

    def _lines_from_detail(self, det, sname, source_key, cfg):
        """采集源详情 → 播放线路列表 [(线路名, '选集$地址#…')]
        直链选集：主线直连（parse=0）+「净化」线路（源 player_api，parse=1）
        平台页选集（优酷等）：逐解析线路展开（parse=1 嗅探）"""
        routes = _parser_routes(cfg)
        src_api = _source_api(cfg, source_key)
        out = []
        if not isinstance(det, dict):
            return out
        groups = det.get("episodes") or []
        if not isinstance(groups, list):
            return out
        multi = len(groups) > 1
        for gi, g in enumerate(groups):
            if not isinstance(g, dict):
                continue
            eps = []
            seen = set()
            for ep in g.get("episodes") or []:
                if not isinstance(ep, dict):
                    continue
                nm = _safe(str(ep.get("name") or "").strip())
                u = str(ep.get("url") or "").strip()
                if not nm or not u.startswith("http"):
                    continue
                if u in seen:
                    continue
                seen.add(u)
                eps.append((nm, u))
            if not eps:
                continue
            if multi:
                gname = str(g.get("group") or g.get("name") or ("线路%d" % (gi + 1)))
                base = "%s·%s" % (sname, gname)
            else:
                base = sname
            if all(_is_direct(u) for _, u in eps):
                out.append((_safe(base), "#".join(n + "$" + u for n, u in eps)))
                if src_api:
                    out.append((_safe(base + "·净化"),
                                "#".join(n + "$" + src_api + _enc(u) for n, u in eps)))
            else:
                apis = list(routes)
                if src_api and all(a != src_api for _, a in apis):
                    apis.insert(0, ("默认", src_api))
                for rn, ra in apis:
                    out.append((_safe("%s·%s" % (base, rn)),
                                "#".join(n + "$" + ra + _enc(u) for n, u in eps)))
        return out

    def _apply_detail(self, vod, det, title):
        if isinstance(det, dict):
            vod["vod_name"] = det.get("name") or vod.get("vod_name") or title
            if det.get("pic"):
                vod["vod_pic"] = det.get("pic")
            vod["vod_year"] = str(det.get("year") or "")[:4] or vod.get("vod_year") or ""
            if det.get("actor"):
                vod["vod_actor"] = det.get("actor")
            if det.get("director"):
                vod["vod_director"] = det.get("director")
            if det.get("area"):
                vod["vod_area"] = det.get("area")
            content = _clean(det.get("content") or "")
            if content:
                vod["vod_content"] = content

    def detailContent(self, ids):
        if isinstance(ids, list):
            vid = ids[0] if ids else ""
        else:
            vid = ids
        vid = (vid or "").strip()
        deadline = time.time() + METHOD_BUDGET
        vod = {"vod_id": vid, "vod_name": "", "vod_pic": "", "vod_year": "",
               "vod_area": "", "vod_actor": "", "vod_director": "", "vod_content": "",
               "vod_play_from": "", "vod_play_url": "", "type_name": "影视"}
        if vid.startswith(HOST + "/watch.php"):
            q = _parse_query(vid)
            title = q.get("title") or ""
            media = q.get("media") or ""
            if media.startswith("tmdb:"):
                mt = media.split(":")[1] if ":" in media else ""
                vod["type_name"] = "电影" if mt == "movie" else ("剧集" if mt == "tv" else "影视")
            vod["vod_name"] = title
            vod["vod_pic"] = q.get("pic") or ""
            lines = []
            cfg = _load_config(deadline)
            picked = []
            chosen = {}
            data = _get_json(_search_url(title, 1), deadline)
            if data and not data.get("need_captcha"):
                for row in data.get("results") or []:
                    if not isinstance(row, dict):
                        continue
                    s = row.get("source")
                    if not s or row.get("id") is None:
                        continue
                    if s not in chosen:
                        chosen[s] = row
                        picked.append(s)
                    elif str(chosen[s].get("name") or "") != title and str(row.get("name") or "") == title:
                        chosen[s] = row
            meta_done = False
            for s in picked[:MAX_SOURCES]:
                if time.time() > deadline - 4.0:
                    break
                row = chosen[s]
                d = _get_json(_detail_url(s, row["id"]), deadline)
                det = None
                if d and not d.get("need_captcha"):
                    dets = d.get("details") or []
                    det = dets[0] if dets and isinstance(dets[0], dict) else None
                if det is None:
                    continue
                if not meta_done:
                    self._apply_detail(vod, det, title)
                    vod["vod_name"] = det.get("name") or title
                    meta_done = True
                base = str(row.get("source_name") or _source_name(cfg, s) or s)
                got = self._lines_from_detail(det, base, s, cfg)
                for ln in got:
                    if len(lines) >= MAX_TOTAL_LINES:
                        break
                    lines.append(ln)
                if len(lines) >= MAX_TOTAL_LINES:
                    break
            if not lines:
                nm = _safe(title or "洛雪TV播放")
                lines = [(nm, nm + "$" + vid)]
        elif vid.startswith(HOST + "/play.php"):
            q = _parse_query(vid)
            source = q.get("source") or ""
            sid = q.get("id") or ""
            title = q.get("title") or ""
            vod["vod_name"] = title
            vod["vod_pic"] = q.get("pic") or ""
            lines = []
            if source and sid:
                d = _get_json(_detail_url(source, sid), deadline)
                det = None
                if d and not d.get("need_captcha"):
                    dets = d.get("details") or []
                    det = dets[0] if dets and isinstance(dets[0], dict) else None
                if det is not None:
                    self._apply_detail(vod, det, title)
                    vod["vod_name"] = det.get("name") or title
                    cfg = _load_config(deadline)
                    base = str(det.get("source_name") or _source_name(cfg, source) or source or "采集线路")
                    lines = self._lines_from_detail(det, base, source, cfg)
                    if len(lines) > MAX_TOTAL_LINES:
                        lines = lines[:MAX_TOTAL_LINES]
            if not lines:
                nm = _safe(title or "立即播放")
                lines = [(_safe(title or "洛雪TV"), nm + "$" + vid)]
        else:
            return {"list": []}
        vod["vod_play_from"] = "$$$".join(l[0] for l in lines)
        vod["vod_play_url"] = "$$$".join(l[1] for l in lines)
        return {"list": [vod]}

    def playerContent(self, flag, id, vipFlags):
        url = id or ""
        if _is_direct(url):
            return {"parse": 0, "playUrl": "", "url": url,
                    "header": {"User-Agent": PLAYER_UA}}
        return {"parse": 1, "playUrl": "", "url": url, "header": {"User-Agent": UA}}

    def localProxy(self, params):
        return None

    def proxy(self, params):
        return None


# ================= 离线自测（python3 lxyy.py 直接运行；fixture 取自 2026-11-03 真实接口响应样本） =================
if __name__ == "__main__":
    THROTTLE = 0.0

    FX_TMDB = {"page": 1, "total_pages": 500, "total_results": 10000, "results": [
        {"id": 155, "title": "蝙蝠侠：黑暗骑士", "poster_path": "/qYB7QqwT1NtTW9aCwtopGy80rmA.jpg",
         "release_date": "2008-07-16", "vote_average": 8.539},
        {"id": 791523, "title": "荒野丛林", "poster_path": "/z5MMAxbQO2nCvBU8BqHgoY1zKdD.jpg",
         "release_date": "2026-10-19", "vote_average": 8.6},
        {"id": 969681, "title": "蜘蛛侠：崭新之日", "poster_path": "/9zFVOpQ0QSg0pOHQdFtNj7NDamp.jpg",
         "release_date": "2026-07-29", "vote_average": 8.486},
    ]}
    FX_TREND = {"page": 1, "results": [
        {"id": 106449, "name": "凡人修仙传", "media_type": "tv", "poster_path": "/u1VRjvvCIVwb1MUhoxSAUimhoKZ.jpg",
         "first_air_date": "2020-09-25", "vote_average": 8.2},
    ]}
    FX_CONFIG = {"success": True, "official_source": "qilin", "official_routes": [
        {"id": "official_default", "name": "默认解析", "api": "https://svip.qlplayer.cyou/?url=", "type": "iframe"},
        {"id": "official_musbpyqz", "name": "洛雪4K", "api": "/json-player.php?route=official_musbpyqz&url=", "type": "json"},
        {"id": "official_muh2fkp2", "name": "蓝光", "api": "/json-player.php?route=official_muh2fkp2&url=", "type": "json"},
        {"id": "official_mv83mv2y", "name": "TXNP", "api": "https://art.txnp.cn/?url=", "type": "iframe"},
        {"id": "official_mugf3fgl", "name": "闪电", "api": "https://bfq.txnp.cn/excessive?url=", "type": "iframe"},
        {"id": "official_muh2ffwq", "name": "m1907", "api": "https://im1907.top/?jx=", "type": "iframe", "hide_mobile": True},
        {"id": "official_mugf3kf6", "name": "洛雪聚合", "api": "https://jx.lxyy.club/index.php?url=", "type": "iframe"},
    ], "sources": {
        "qilin": {"name": "官采蓝光", "player_api": "https://svip.qlplayer.cyou/?url="},
        "dytt": {"name": "电影天堂", "player_api": "https://jimaoys99.com/parse?url="},
        "jl": {"name": "自营🔥", "player_api": "https://jimaoys99.com/parse?url="},
    }}
    FX_SEARCH = {"keyword": "凡人修仙传", "page": 1, "results": [
        {"area": "", "id": 7883, "name": "凡人修仙传", "pic": "", "remarks": "全剧集",
         "source": "qilin", "source_name": "官采蓝光", "type": "国产剧", "year": "2025"},
        {"area": "", "id": 8298, "name": "凡人修仙传", "pic": "", "remarks": "全130集",
         "source": "dytt", "source_name": "电影天堂", "type": "国产动漫", "year": "2020"},
        {"area": "中国大陆", "id": 629423138538520578, "name": "凡人修仙传", "pic": "https://example.com/a.jpg",
         "remarks": "更新至22集", "source": "jl", "source_name": "自营🔥", "type": "中国动漫", "year": "2026"},
        {"area": "", "id": 16789, "name": "凡人修仙传", "pic": "", "remarks": "HD",
         "source": "mj", "source_name": "4k60帧🔥", "type": "国产动漫", "year": "2020"},
        {"area": "", "id": 100, "name": "凡人修仙传", "pic": "", "remarks": "全130集",
         "source": "360zy", "source_name": "360资源", "type": "国产动漫", "year": "2020"},
        {"area": "", "id": 200, "name": "凡人修仙传", "pic": "", "remarks": "HD",
         "source": "ik", "source_name": "ikun", "type": "国产动漫", "year": "2020"},
        {"area": "", "id": 300, "name": "凡人修仙传", "pic": "", "remarks": "HD",
         "source": "md", "source_name": "魔都", "type": "国产动漫", "year": "2020"},
        {"area": "", "id": 400, "name": "凡人修仙传", "pic": "", "remarks": "正片",
         "source": "fy", "source_name": "官方源", "type": "动画", "year": "2020"},
    ]}
    FX_DETAIL_DYTT = {"cache_ttl": 3600, "details": [{
        "actor": "钱文青,杨天翔", "area": "大陆", "director": "伍镇焯,王裕仁",
        "content": "<p>平凡少年韩立出生贫困……拜别家人后……</p>",
        "name": "凡人修仙传", "pic": "", "year": "2020",
        "episodes": [{"episodes": [
            {"name": "第01集", "url": "https://vip.dytt-cinema.com/20250215/2976_a209ca7b/index.m3u8"},
            {"name": "第02集$花絮#", "url": "https://vip.dytt-cinema.com/20250215/2975_2ef3e50f/index.m3u8"},
            {"name": "第03集", "url": "https://vip.dytt-cinema.com/20250215/2974_67880768/index.m3u8"},
            {"name": "第03集", "url": "https://vip.dytt-cinema.com/20250215/2974_67880768/index.m3u8"},
        ]}],
    }]}
    FX_DETAIL_QILIN = {"cache_ttl": 3600, "details": [{
        "actor": "杨洋,金晨", "area": "中国", "director": "杨阳",
        "content": "该剧改编自忘语的同名小说。",
        "name": "凡人修仙传", "pic": "http://m.ykimg.com/x.jpg", "year": "2025",
        "episodes": [{"group": "youku", "episodes": [
            {"name": "1", "url": "https://v.youku.com/v_show/id_XNjQ3MTc1MDYwMA==.html"},
            {"name": "2", "url": "https://v.youku.com/v_show/id_XNjQ4MTIwOTE2NA==.html"},
        ]}],
    }]}

    FX_DETAIL_JL = {"cache_ttl": 3600, "details": [{
        "actor": "", "area": "中国大陆", "director": "",
        "content": "凡人修仙传 年番。",
        "name": "凡人修仙传", "pic": "", "year": "2026",
        "episodes": [{"episodes": [
            {"name": "第01集", "url": "https://jimao.example/1/index.m3u8"},
            {"name": "第02集", "url": "https://jimao.example/2/index.m3u8"},
        ]}],
    }]}

    FX_DETAIL_GEN = {"cache_ttl": 3600, "details": [{
        "name": "凡人修仙传", "year": "2020",
        "episodes": [{"episodes": [
            {"name": "第01集", "url": "https://gen.example/2026/1/index.m3u8"},
        ]}],
    }]}

    def fake_get(url, deadline=None):
        if "action=config" in url:
            return json.dumps(FX_CONFIG)
        if "action=search" in url:
            if "wd=%E6%96%AD%E7%BD%91" in url:
                return None
            return json.dumps(FX_SEARCH)
        if "action=detail" in url:
            if "source=dytt" in url:
                return json.dumps(FX_DETAIL_DYTT)
            if "source=qilin" in url:
                return json.dumps(FX_DETAIL_QILIN)
            if "source=jl" in url:
                return json.dumps(FX_DETAIL_JL)
            if ("source=mj" in url or "source=360zy" in url or "source=ik" in url
                    or "source=md" in url or "source=fy" in url):
                return json.dumps(FX_DETAIL_GEN)
            return None
        if "tmdb.php" in url:
            if "trending" in url:
                return json.dumps(FX_TREND)
            return json.dumps(FX_TMDB)
        return None

    _get = fake_get

    passed = [0]
    failed = [0]

    def check(name, cond):
        if cond:
            passed[0] += 1
        else:
            failed[0] += 1
            print("FAIL: %s" % name)

    sp = Spider().init()
    r = sp.homeContent({})
    check("homeContent 39 分类零网络", len(r.get("class") or []) == 39 and not r.get("list"))
    check("分类无 null 字段", all(c.get("type_id") and c.get("type_name") for c in r["class"]))

    r = sp.categoryContent("movie-all", 1, {}, {})
    lst = r.get("list") or []
    check("categoryContent 电影·全部 3 条", len(lst) == 3)
    if lst:
        check("vod_id 为 watch.php 绝对 URL", lst[0]["vod_id"].startswith(HOST + "/watch.php?title="))
        check("vod_id 含 tmdb:movie 引用", "155" in lst[0]["vod_id"] and "tmdb" in lst[0]["vod_id"])
        check("vod_pic 为 TMDB 海报", lst[0]["vod_pic"].startswith(IMG_BASE))
        check("无拼接双斜杠", "//watch.php" not in lst[0]["vod_id"].replace("https://", ""))
        check("vod_remarks 含年份", "2008" in lst[0]["vod_remarks"])

    r = sp.categoryContent("tmdb-trending", 1, {}, {})
    lst = r.get("list") or []
    check("trending 走 name/media_type 字段", len(lst) == 1 and lst[0]["vod_name"] == "凡人修仙传")
    check("未知分类返回空列表", (sp.categoryContent("no-such", 1, {}, {}).get("list") or []) == [])

    r = sp.searchContent("凡人修仙传", False)
    lst = r.get("list") or []
    check("searchContent 出采集源结果", len(lst) == 8)
    if lst:
        check("搜索 vod_id 为 play.php 绝对 URL", lst[0]["vod_id"].startswith(HOST + "/play.php?source="))

    wid = _watch_url("凡人修仙传", "tv", 106449, "https://image.tmdb.org/t/p/w342/u1VR.jpg")
    r = sp.detailContent([wid])
    vod = (r.get("list") or [None])[0]
    check("detailContent 返回 1 条", vod is not None)
    if vod:
        pf = vod["vod_play_from"].split("$$$")
        pu = vod["vod_play_url"].split("$$$")
        check("线路数 18（官采4解析+普通源7×2）", len(pf) == 18 and len(pu) == 18)
        check("普通线路全量展开（网络公开收集）",
              all(n in pf for n in ["4k60帧🔥", "自营🔥", "360资源", "电影天堂", "ikun", "魔都", "官方源"]))
        check("mj 净化线路走源 player_api",
              any("https://mujizybf.com/m3u8/?url=https%3A%2F%2Fgen.example" in u for u in pu))
        check("官采平台页按解析线路展开", "官采蓝光·默认解析" in pf and "官采蓝光·TXNP" in pf
              and "官采蓝光·闪电" in pf and "官采蓝光·洛雪聚合" in pf)
        check("json 线路（洛雪4K/蓝光）不接入", not [l for l in pf if l.endswith("·洛雪4K") or l.endswith("·蓝光")])
        check("hide_mobile 线路不接入", "m1907" not in vod["vod_play_from"])
        check("直链源双线路（直连+净化）", "电影天堂" in pf and "电影天堂·净化" in pf)
        qi = pf.index("官采蓝光·默认解析")
        check("解析线路拼法 api+enc(url)",
              ("https://svip.qlplayer.cyou/?url=https%3A%2F%2Fv.youku.com%2Fv_show%2F"
               "id_XNjQ3MTc1MDYwMA%3D%3D.html") in pu[qi])
        check("选集名保持原网显示名", "1$https://svip.qlplayer.cyou/?url=" in pu[qi])
        di = pf.index("电影天堂")
        check("m3u8 直链进选集", "vip.dytt-cinema.com" in pu[di])
        check("净化线路走源 player_api", "https://jimaoys99.com/parse?url=https%3A%2F%2Fvip.dytt-cinema.com" in pu[di + 1])
        check("选集名 $# 转全角", "第02集＄花絮＃" in pu[di])
        check("同地址选集去重", pu[di].count("2974_67880768") == 1)
        check("简介去标签（取首个成功源）", "<p>" not in vod["vod_content"] and "忘语" in vod["vod_content"])
        check("演职字段（首个成功源）", "杨洋" in vod["vod_actor"] and "杨阳" in vod["vod_director"])
        check("type_name", vod["type_name"] == "剧集")
        check("多源取详情元数据（官采年份2025）", vod["vod_year"] == "2025" and vod["vod_pic"] == "http://m.ykimg.com/x.jpg")

    r = sp.detailContent([_watch_url("断网测试", "tv", 1, "")])
    vod = (r.get("list") or [{}])[0]
    check("详情失败保底一条线路", "$$$" not in vod.get("vod_play_from", "") and
          vod.get("vod_play_from") == "断网测试" and "watch.php" in vod.get("vod_play_url", ""))
    r = sp.detailContent([_play_url("dytt", 8298, "凡人修仙传", "")])
    vod = (r.get("list") or [{}])[0]
    check("play.php 直达详情出直连+净化线路",
          "第01集$https://vip.dytt-cinema.com" in vod.get("vod_play_url", "")
          and "电影天堂·净化" in vod.get("vod_play_from", ""))

    pr = sp.playerContent("电影天堂", "https://vip.dytt-cinema.com/20250215/2976_a209ca7b/index.m3u8", {})
    check("m3u8 parse=0 + okhttp UA", pr["parse"] == 0 and pr["header"]["User-Agent"].startswith("okhttp"))
    pr = sp.playerContent("官采蓝光", "https://svip.qlplayer.cyou/?url=https%3A%2F%2Fvip.dytt-cinema.com%2F20250215%2F2976_a209ca7b%2Findex.m3u8", {})
    check("解析页地址（query 含 m3u8）parse=1", pr["parse"] == 1)
    pr = sp.playerContent("洛雪TV", wid, {})
    check("watch.php 兜底 parse=1", pr["parse"] == 1)
    check("isVideoFormat 按路径判断", sp.isVideoFormat("https://svip.qlplayer.cyou/?url=https%3A%2F%2Fx.m3u8") is False)

    print("lxyy %s self-test: %d passed, %d failed" % (VERSION, passed[0], failed[0]))
    sys.exit(1 if failed[0] else 0)
