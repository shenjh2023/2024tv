# -*- coding: utf-8 -*-
"""秒看电影（miaokan.cc）TVBox / CatVodSpider 源

站点是 MacCMS 变体（ewave 模板）：
  列表  /mk/<分类>/、/label/new/        —— 一页给全，无翻页
  搜索  /sosomk/-------------/?wd=关键词
  详情  /miaokan/<id>/                  —— 播放列表 tab = 线路，条目 = 集数
  播放  /mkvod/<id>-<线路>-<集数>/       —— 页面里 var player_aaaa={...}.url 就是 m3u8
m3u8 的 master 里是「根路径」的相对地址，这里会先解成绝对地址再交给播放器。
"""
import json
import re
import urllib.parse

import requests

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

try:
    from base.spider import Spider as BaseSpider
except ImportError:
    class BaseSpider:
        pass


class Spider(BaseSpider):
    BASE_URL = "https://miaokan.cc"
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": BASE_URL + "/",
    }

    def __init__(self):
        super().__init__()
        self.name = "秒看电影"
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self._class_cache = None

    def init(self, extend="{}"):
        return None

    def getName(self):
        return self.name

    def homeContent(self, filter):
        html_text = self._get(self.BASE_URL + "/label/new/")
        return {"class": self._classes(), "filters": {}, "list": self._parse_list(html_text),
                "parse": 0, "jx": 0}

    def homeVideoContent(self):
        return {"list": self._parse_list(self._get(self.BASE_URL + "/label/new/"))}

    def categoryContent(self, tid, pg, filter, extend):
        path = str(tid or "label/new").strip("/")
        html_text = self._get(self.BASE_URL + "/" + path + "/")
        data = self._parse_list(html_text)
        return {"page": 1, "pagecount": 1, "limit": len(data) or 36, "total": len(data),
                "list": data, "parse": 0, "jx": 0}

    def detailContent(self, ids):
        result = {"list": [], "parse": 0, "jx": 0}
        if not ids:
            return result
        raw = str(ids[0])
        url = raw if raw.startswith("http") else self.BASE_URL + "/miaokan/" + raw.strip("/") + "/"
        html_text = self._get(url)
        if not html_text:
            return result
        name = self._clean(self._match(html_text, r'class="vod-info[\s\S]{0,800}?<h3>\s*<a[^>]*>(.*?)</a>')
                           or self._match(html_text, r'<title>(.*?)</title>').split("-")[0])
        pic = self._match(html_text, r'class="vod-info[\s\S]{0,800}?data-original="([^"]+)"')
        content = self._clean(self._match(html_text, r'<meta\s+name="description"\s+content="([^"]*)"'))
        info = {}
        for label in ("分类", "地区", "年份", "导演", "主演", "更新"):
            v = self._match(html_text, label + r'：\s*(?:<[^>]+>)*\s*([^<]{0,120}?)\s*(?:<|$)')
            if v:
                info[label] = self._clean(v)
        remarks = info.get("更新") or self._clean(self._match(html_text, r'item-status[^>]*>([^<]{0,20})<'))
        froms, urls = self._playlist(html_text)
        if not urls:
            return result
        # YZZY 这条 CDN 对不少 IP 直接 403，排到最后，别让播放器默认踩坑
        if len(froms) > 1:
            pairs = sorted(zip(froms, urls), key=lambda x: 1 if x[0].upper().startswith("YZZY") else 0)
            froms = [x[0] for x in pairs]
            urls = [x[1] for x in pairs]
        result["list"].append({"vod_id": url, "vod_name": name, "vod_pic": pic,
                               "type_name": info.get("分类", ""), "vod_year": info.get("年份", ""),
                               "vod_area": info.get("地区", ""), "vod_remarks": remarks,
                               "vod_actor": info.get("主演", ""), "vod_director": info.get("导演", ""),
                               "vod_content": content or name,
                               "vod_play_from": "$$$".join(froms),
                               "vod_play_url": "$$$".join(urls)})
        return result

    def searchContent(self, key, quick, pg="1"):
        # 搜索结果页是 JS 渲染的，走站点的 suggest 接口
        q = urllib.parse.quote(str(key or ""))
        data = []
        try:
            r = self.session.get(self.BASE_URL + "/index.php/ajax/suggest?mid=1&wd=" + q,
                                 headers=self.HEADERS, timeout=20, verify=False)
            for it in (r.json() or {}).get("list") or []:
                data.append({"vod_id": self.BASE_URL + "/miaokan/" + str(it.get("id")) + "/",
                             "vod_name": it.get("name") or "", "vod_pic": it.get("pic") or "",
                             "vod_remarks": ""})
        except Exception:
            data = []
        if not data:
            data = self._parse_list(self._get(self.BASE_URL + "/sosomk/-------------/?wd=" + q))
        return {"page": 1, "pagecount": 1, "limit": len(data) or 36, "total": len(data),
                "list": data, "parse": 0, "jx": 0}

    def playerContent(self, flag, id, vipFlags):
        hdr = {"User-Agent": self.HEADERS["User-Agent"], "Referer": self.BASE_URL + "/"}
        result = {"parse": 0, "playUrl": "", "url": id or "", "jx": 0, "header": hdr}
        if not id:
            return result
        if ".m3u8" in id or ".mp4" in id:
            result["url"] = self._resolve_master(id)
            return result
        raw = str(id)
        url = raw if raw.startswith("http") else self.BASE_URL + raw
        play = self._m3u8_of(url)
        if play and self._alive(play):
            result["url"] = self._resolve_master(play)
            return result
        alt = self._alt_line(raw)          # 这条线挂了，换同集的其它线路试
        if alt:
            result["url"] = self._resolve_master(alt)
            return result
        if play:
            result["url"] = self._resolve_master(play)
            return result
        result["parse"] = 1
        return result

    def isVideoFormat(self, url):
        return bool(re.search(r'\.(m3u8|mp4)(\?|$)', str(url or ""), re.I))

    def manualVideoCheck(self):
        return False

    # ---------------- 内部 ----------------

    def _classes(self):
        if self._class_cache:
            return self._class_cache
        self._class_cache = [
            {"type_id": "label/new", "type_name": "最近更新"},
            {"type_id": "mk/dianying", "type_name": "电影"},
            {"type_id": "mk/lianxuju", "type_name": "电视剧"},
            {"type_id": "mk/zongyi", "type_name": "综艺"},
            {"type_id": "mk/dongman", "type_name": "动漫"},
            {"type_id": "mk/duanju", "type_name": "短剧"},
            {"type_id": "mk/yingshijieshuo", "type_name": "影视解说"},
            {"type_id": "label/ranking", "type_name": "排行榜"},
        ]
        return self._class_cache

    def _parse_list(self, html_text):
        data, seen = [], set()
        # 站点有三种列表样式（卡片 / 排行榜行 / 搜索行），统一按带 title 的详情链接解析
        for m in re.finditer(r'<a[^>]+href="/miaokan/(\d+)/"[^>]*>', html_text or ""):
            tag = m.group(0)
            vid = m.group(1)
            if vid in seen or "title=" not in tag:
                continue
            win = (html_text or "")[m.start():m.start() + 800]
            name = self._clean(self._match(tag, r'title="([^"]+)"'))
            pic = (self._match(win, r'data-original="([^"]+)"')
                   or self._match(win, r'data-src="([^"]+)"')
                   or self._match(win, r'(?:src)="(https?://[^"]+\.(?:jpg|jpeg|png|webp))"'))
            remarks = self._clean(self._match(win, r'class="(?:item-status|text-overflow)"[^>]*>([^<]{0,20})<'))
            if not name:
                continue
            seen.add(vid)
            data.append({"vod_id": self.BASE_URL + "/miaokan/" + vid + "/",
                         "vod_name": name, "vod_pic": pic, "vod_remarks": remarks})
        return data

    def _playlist(self, html_text):
        """返回 (线路名列表, 线路地址组列表)。播放列表 tab 的 sid 就是线路号。"""
        froms, urls = [], []
        tabs = re.findall(r'data-target="#ewave-playlist-(\d+)"[^>]*>\s*([^<]{1,16})\s*<em', html_text or "")
        if not tabs:
            tabs = [(m, "线路" + m) for m in re.findall(r'id="ewave-playlist-(\d+)"', html_text or "")]
        for sid, label in tabs:
            m = re.search(r'id="ewave-playlist-%s"[\s\S]*?</ul>' % re.escape(sid), html_text or "")
            if not m:
                continue
            eps = re.findall(r'href="(/mkvod/\d+-%s-\d+/)"[^>]*>\s*([^<]{1,20})\s*<' % re.escape(sid), m.group(0))
            if not eps:
                continue
            froms.append(self._clean(label))
            urls.append("#".join([self._clean(t) + "$" + self.BASE_URL + u for u, t in eps]))
        return froms, urls

    def _m3u8_of(self, play_page):
        html_text = self._get(play_page)
        m = re.search(r'var\s+player_aaaa\s*=\s*(\{.*?\})</script>', html_text or "", re.S)
        if m:
            try:
                d = json.loads(m.group(1))
            except Exception:
                d = {}
            if d.get("url"):
                return d["url"]
        m = re.search(r'(https?://[^"\'\\\s]+\.m3u8[^"\'\\\s]*)', html_text or "")
        return m.group(1) if m else ""

    def _alive(self, play):
        try:
            r = self.session.get(play, headers={"User-Agent": self.HEADERS["User-Agent"],
                                                "Referer": self.BASE_URL + "/"},
                                 timeout=12, verify=False)
            return r.status_code == 200 and "#EXTM3U" in (r.text or "")
        except Exception:
            return False

    def _alt_line(self, raw):
        """同一条目其它线路：/mkvod/<id>-<sid>-<nid>/，sid 换一个再试。"""
        m = re.search(r'/mkvod/(\d+)-(\d+)-(\d+)/', str(raw))
        if not m:
            return ""
        vid, sid, nid = m.group(1), m.group(2), m.group(3)
        for other in range(1, 9):
            if str(other) == sid:
                continue
            play = self._m3u8_of("%s/mkvod/%s-%s-%s/" % (self.BASE_URL, vid, other, nid))
            if play and self._alive(play):
                return play
        return ""

    def _resolve_master(self, url):
        """master m3u8 里的码率地址是根路径，解成绝对地址，省得播放器拼错。"""
        if not url or not url.startswith("http") or ".m3u8" not in url:
            return url
        try:
            r = self.session.get(url, headers=self.HEADERS, timeout=12, verify=False)
            body = r.text or ""
            if "#EXT-X-STREAM-INF" not in body:
                return url
            best, best_bw = "", -1
            for m in re.finditer(r'#EXT-X-STREAM-INF:([^\n]*)\n([^\n#]+)', body):
                bw = self._to_int(re.search(r'BANDWIDTH=(\d+)', m.group(1)).group(1) if re.search(r'BANDWIDTH=(\d+)', m.group(1)) else 0)
                if bw > best_bw:
                    best, best_bw = m.group(2).strip(), bw
            if best:
                return urllib.parse.urljoin(url, best)
        except Exception:
            pass
        return url

    def _get(self, url):
        try:
            r = self.session.get(url, headers=self.HEADERS, timeout=20, verify=False)
            r.encoding = "utf-8"
            if r.status_code < 400:
                return r.text
        except Exception:
            pass
        return ""

    def _match(self, text, pattern):
        m = re.search(pattern, text or "", re.S | re.I)
        return m.group(1).strip() if m and m.lastindex else ""

    def _clean(self, text):
        text = re.sub(r'<.*?>', '', text or '')
        for a, b in (('&nbsp;', ' '), ('&amp;', '&'), ('&#038;', '&'), ('&quot;', '"'), ('&#039;', "'")):
            text = text.replace(a, b)
        return re.sub(r'\s+', ' ', text).strip()

    def _to_int(self, v, default=0):
        try:
            return int(str(v).strip())
        except Exception:
            return default
