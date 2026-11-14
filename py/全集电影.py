# -*- coding: utf-8 -*-
# TVBox Python 源：全集影视网 www.qjdy.cc
# 搜索走 POST /s/ ，分类第1页 /dy/ ，第N页 /dy/N.html

from base.spider import Spider
import re
import requests

HOST = "https://www.qjdy.cc"
UA = "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"


class Spider(Spider):

    def getName(self):
        return "全集影视"

    def init(self, extend=""):
        self.extend = extend or ""
        m = re.search(r"https?://[^\"'\s]+", self.extend)
        self.host = (m.group(0) if m else HOST).rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": UA,
            "Referer": self.host + "/",
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
        })
        return None

    # ---------------- 基础请求 ----------------

    def _get(self, url):
        try:
            r = self.s.get(url, timeout=15)
            r.encoding = "utf-8"
            return r.text or ""
        except Exception:
            return ""

    def _post(self, url, data):
        try:
            r = self.s.post(url, data=data, timeout=15)
            r.encoding = "utf-8"
            return r.text or ""
        except Exception:
            return ""

    # ---------------- 解析列表 ----------------

    def _items(self, html):
        out = []
        if not html:
            return out
        seen = set()
        for li in re.findall(r"<li>(.*?)</li>", html, re.S):
            mid = re.search(r"href='(/mov/(\d+)/?)'", li)
            if not mid:
                continue
            vid = mid.group(2)
            if vid in seen:
                continue
            img = re.search(r"data-src='([^']+)'", li)
            if not img:
                img = re.search(r"<img[^>]+src='([^']+)'", li)
            pic = img.group(1) if img else ""
            if pic.endswith("loading.gif"):
                pic = ""
            nm = re.search(r"<h2>(.*?)</h2>", li)
            name = nm.group(1).strip() if nm else ""
            if not name:
                alt = re.search(r"alt='([^']*)'", li)
                name = alt.group(1).strip() if alt else ""
            note = re.search(r"<label>(.*?)</label>", li)
            remark = note.group(1).strip() if note else ""
            seen.add(vid)
            out.append({
                "vod_id": vid,
                "vod_name": name,
                "vod_pic": pic,
                "vod_remarks": remark,
            })
        return out

    # ---------------- 首页 ----------------

    def homeContent(self, filter):
        cats = [
            {"type_id": "dy", "type_name": "电影"},
            {"type_id": "dsj", "type_name": "电视剧"},
            {"type_id": "dm", "type_name": "动漫"},
            {"type_id": "zy", "type_name": "综艺"},
            {"type_id": "xzj", "type_name": "其他"},
            {"type_id": "dongzuopian", "type_name": "动作片"},
            {"type_id": "xijupian", "type_name": "喜剧片"},
            {"type_id": "aiqingpian", "type_name": "爱情片"},
            {"type_id": "kehuanpian", "type_name": "科幻片"},
            {"type_id": "kongbupian", "type_name": "恐怖片"},
            {"type_id": "juqingpian", "type_name": "剧情片"},
            {"type_id": "guoshanju", "type_name": "国产剧"},
            {"type_id": "gangtaiju", "type_name": "港台剧"},
            {"type_id": "rihanju", "type_name": "日韩剧"},
            {"type_id": "oumeiju", "type_name": "欧美剧"},
            {"type_id": "haiwaiju", "type_name": "海外剧"},
            {"type_id": "duanju", "type_name": "短剧"},
        ]
        html = self._get(self.host + "/")
        videos = self._items(html)[:36]
        return {"class": cats, "filters": {}, "list": videos}

    def homeVideoContent(self):
        html = self._get(self.host + "/")
        return {"list": self._items(html)[:36]}

    # ---------------- 分类 ----------------

    def categoryContent(self, tid, pg, filter, extend):
        try:
            page = int(pg)
        except Exception:
            page = 1
        path = (tid or "dy").strip().strip("/")
        if page <= 1:
            url = "%s/%s/" % (self.host, path)
        else:
            url = "%s/%s/%d.html" % (self.host, path, page)
        html = self._get(url)
        videos = self._items(html)
        has_next = ("/%s/%d.html" % (path, page + 1)) in html
        return {
            "page": page,
            "pagecount": page + 1 if has_next else page,
            "limit": len(videos),
            "total": 99999 if has_next else (page - 1) * len(videos) + len(videos),
            "list": videos,
        }

    # ---------------- 详情 ----------------

    def detailContent(self, ids):
        vid = str(ids[0])
        vid = re.sub(r"\D", "", vid)
        url = "%s/mov/%s/" % (self.host, vid)
        html = self._get(url)
        if not html:
            return {"list": []}

        name = ""
        m = re.search(r"<h1>(.*?)</h1>", html, re.S)
        if m:
            name = re.sub(r"<.*?>", "", m.group(1)).strip()
        pic = ""
        m = re.search(r"<div class='info'><img[^>]+src='([^']+)'", html)
        if m:
            pic = m.group(1)
        content = ""
        m = re.search(r"剧情介绍[:：]?(.*?)<a ", html, re.S)
        if not m:
            m = re.search(r"<meta itemprop='description'[^>]+content='([^']*)'", html)
        if m:
            content = re.sub(r"<.*?>", "", m.group(1)).strip()

        actor = ""
        m = re.search(r"影片演员：<a[^>]*>(.*?)</a>", html, re.S)
        if m:
            actor = m.group(1).strip()
        area = ""
        m = re.search(r"影片地区：<a[^>]*>(.*?)</a>", html, re.S)
        if m:
            area = m.group(1).strip()
        year = ""
        m = re.search(r"上映时间：<a[^>]*>(.*?)</a>", html, re.S)
        if m:
            y = re.search(r"(\d{4})", m.group(1))
            year = y.group(1) if y else ""
        type_name = ""
        m = re.search(r"影片类型：<a[^>]*>(.*?)</a>", html, re.S)
        if m:
            type_name = m.group(1).strip()

        # 线路名
        labs = re.findall(r"<div class='lab' id='v_lab'>(.*?)</div>", html, re.S)
        flags = []
        if labs:
            flags = [re.sub(r"<.*?>", "", x).strip() for x in re.findall(r"<label>(.*?)</label>", labs[0], re.S)]
        if not flags:
            flags = ["线路1"]

        # 各线路剧集列表
        box = re.search(r"<div class='v_box'>(.*?)</div>", html, re.S)
        play_from = []
        play_url = []
        if box:
            uls = re.findall(r"<ul class='vurls'>(.*?)</ul>", box.group(1), re.S)
            for i, ul in enumerate(uls):
                eps = []
                for href, ep in re.findall(r"href='(/play/\d+/\d+/\d+/)'[^>]*>(.*?)</a>", ul, re.S):
                    ep_name = re.sub(r"<.*?>", "", ep).strip()
                    if not ep_name:
                        continue
                    eps.append("%s$%s%s" % (ep_name, self.host, href))
                if not eps:
                    continue
                flag = flags[i] if i < len(flags) and flags[i] else ("线路%d" % (i + 1))
                play_from.append(flag)
                play_url.append("#".join(eps))

        vod = {
            "vod_id": vid,
            "vod_name": name,
            "vod_pic": pic,
            "type_name": type_name,
            "vod_year": year,
            "vod_area": area,
            "vod_actor": actor,
            "vod_content": content,
            "vod_play_from": "$$$".join(play_from),
            "vod_play_url": "$$$".join(play_url),
        }
        return {"list": [vod]}

    # ---------------- 搜索 ----------------

    def searchContent(self, key, quick, pg="1"):
        try:
            page = int(pg)
        except Exception:
            page = 1
        html = ""
        if page <= 1:
            html = self._post(self.host + "/s/", {"s": key, "skey": ""})
        else:
            html = self._post(self.host + "/s/%d/" % page, {"s": key, "skey": ""})
        return {"list": self._items(html)}

    # ---------------- 播放 ----------------

    def playerContent(self, flag, id, vipFlags):
        url = id if str(id).startswith("http") else (self.host + str(id))
        html = self._get(url)
        surl = ""
        m = re.search(r"var\s+surl\s*=\s*'([^']+)'", html)
        if m:
            surl = m.group(1).strip()
        if not surl:
            m = re.search(r'var\s+surl\s*=\s*"([^"]+)"', html)
            if m:
                surl = m.group(1).strip()
        if surl and (surl.startswith("http://") or surl.startswith("https://")):
            if ".m3u8" in surl.lower() or ".mp4" in surl.lower():
                return {"parse": 0, "playUrl": "", "url": surl, "header": {"User-Agent": UA}}
            return {
                "parse": 1,
                "playUrl": "https://jx.aidouer.net/?url=",
                "url": surl,
                "header": {"User-Agent": UA},
            }
        return {"parse": 1, "playUrl": "", "url": url, "header": {"User-Agent": UA}}
