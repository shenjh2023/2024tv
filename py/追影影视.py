import requests
from bs4 import BeautifulSoup
import re
import sys
import json
import urllib.parse
import base64
import time
import hashlib
from base.spider import Spider
from urllib.parse import urljoin

sys.path.append('..')

xurl = "https://zhuiying8.cc"
headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 13; M2102J2SC Build/TKQ1.221114.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/144.0.7559.31 Mobile Safari/537.36',
    'Referer': xurl,
}

class Spider(Spider):
    static_filters = {
        "dianying": [
            {"key":"type","name":"类型","value":[{"n":"全部","v":""},{"n":"科幻","v":"科幻"},{"n":"剧情","v":"剧情"},{"n":"惊悚","v":"惊悚"},{"n":"爱情","v":"爱情"},{"n":"古装","v":"古装"},{"n":"动作","v":"动作"},{"n":"悬疑","v":"悬疑"},{"n":"犯罪","v":"犯罪"},{"n":"谍战","v":"谍战"},{"n":"历史","v":"历史"},{"n":"喜剧","v":"喜剧"},{"n":"奇幻","v":"奇幻"},{"n":"家庭","v":"家庭"},{"n":"青春","v":"青春"},{"n":"冒险","v":"冒险"},{"n":"纪录","v":"纪录"},{"n":"动画","v":"动画"},{"n":"人物","v":"人物"},{"n":"文化","v":"文化"},{"n":"其他","v":"其他"}]},
            {"key":"area","name":"地区","value":[{"n":"全部","v":""},{"n":"中国大陆","v":"中国大陆"},{"n":"香港","v":"中国香港"},{"n":"台湾","v":"中国台湾"},{"n":"美国","v":"美国"},{"n":"日本","v":"日本"},{"n":"韩国","v":"韩国"},{"n":"德国","v":"德国"},{"n":"泰国","v":"泰国"},{"n":"英国","v":"英国"},{"n":"法国","v":"法国"},{"n":"意大利","v":"意大利"},{"n":"西班牙","v":"西班牙"}]},
            {"key":"year","name":"年代","value":[{"n":"全部","v":""},{"n":"2026","v":"2026"},{"n":"2025","v":"2025"},{"n":"2024","v":"2024"},{"n":"2023","v":"2023"},{"n":"2022","v":"2022"},{"n":"2021","v":"2021"},{"n":"2020","v":"2020"},{"n":"2019","v":"2019"},{"n":"2018","v":"2018"},{"n":"2017","v":"2017"},{"n":"2016","v":"2016"},{"n":"2015","v":"2015"},{"n":"2014","v":"2014"},{"n":"2013","v":"2013"},{"n":"2012","v":"2012"},{"n":"2011","v":"2011"},{"n":"2010","v":"2010"}]},
            {"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits_week"},{"n":"评分","v":"douban_score"}]}
        ],
        "dianshiju": [
            {"key":"type","name":"类型","value":[{"n":"全部","v":""},{"n":"爱情","v":"爱情"},{"n":"古装","v":"古装"},{"n":"悬疑","v":"悬疑"},{"n":"都市","v":"都市"},{"n":"喜剧","v":"喜剧"},{"n":"战争","v":"战争"},{"n":"剧情","v":"剧情"},{"n":"青春","v":"青春"},{"n":"历史","v":"历史"},{"n":"网剧","v":"网剧"},{"n":"奇幻","v":"奇幻"},{"n":"冒险","v":"冒险"},{"n":"励志","v":"励志"},{"n":"犯罪","v":"犯罪"},{"n":"商战","v":"商战"},{"n":"恐怖","v":"恐怖"},{"n":"穿越","v":"穿越"},{"n":"农村","v":"农村"},{"n":"人物","v":"人物"},{"n":"商业","v":"商业"},{"n":"生活","v":"生活"},{"n":"其他","v":"其他"}]},
            {"key":"area","name":"地区","value":[{"n":"全部","v":""},{"n":"中国","v":"中国大陆"},{"n":"中国香港","v":"中国香港"},{"n":"中国台湾","v":"中国台湾"},{"n":"美国","v":"美国"},{"n":"日本","v":"日本"},{"n":"韩国","v":"韩国"},{"n":"德国","v":"德国"},{"n":"泰国","v":"泰国"},{"n":"英国","v":"英国"},{"n":"法国","v":"法国"},{"n":"新加坡","v":"新加坡"},{"n":"其他","v":"其他"}]},
            {"key":"year","name":"年代","value":[{"n":"全部","v":""},{"n":"2026","v":"2026"},{"n":"2025","v":"2025"},{"n":"2024","v":"2024"},{"n":"2023","v":"2023"},{"n":"2022","v":"2022"},{"n":"2021","v":"2021"},{"n":"2020","v":"2020"},{"n":"2019","v":"2019"},{"n":"2018","v":"2018"},{"n":"2017","v":"2017"},{"n":"2016","v":"2016"},{"n":"2015","v":"2015"},{"n":"2014","v":"2014"},{"n":"2013","v":"2013"},{"n":"2012","v":"2012"},{"n":"2011","v":"2011"},{"n":"2010","v":"2010"}]},
            {"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits_week"},{"n":"评分","v":"douban_score"}]}
        ],
        "zongyi": [
            {"key":"type","name":"类型","value":[{"n":"全部","v":""},{"n":"真人秀","v":"真人秀"},{"n":"脱口秀","v":"脱口秀"},{"n":"喜剧","v":"喜剧"},{"n":"音乐","v":"音乐"},{"n":"爱情","v":"爱情"},{"n":"家庭","v":"家庭"},{"n":"歌舞","v":"歌舞"}]},
            {"key":"area","name":"地区","value":[{"n":"全部","v":""},{"n":"中国大陆","v":"中国大陆"},{"n":"港台","v":"港台"},{"n":"欧美","v":"欧美"},{"n":"韩国","v":"韩国"},{"n":"其他","v":"其他"}]},
            {"key":"year","name":"年代","value":[{"n":"全部","v":""},{"n":"2026","v":"2026"},{"n":"2025","v":"2025"},{"n":"2024","v":"2024"},{"n":"2023","v":"2023"},{"n":"2022","v":"2022"},{"n":"2021","v":"2021"},{"n":"2020","v":"2020"},{"n":"2019","v":"2019"},{"n":"2018","v":"2018"},{"n":"2017","v":"2017"},{"n":"2016","v":"2016"},{"n":"2015","v":"2015"},{"n":"2014","v":"2014"},{"n":"2013","v":"2013"},{"n":"2012","v":"2012"},{"n":"2011","v":"2011"},{"n":"2010","v":"2010"}]},
            {"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits_week"},{"n":"评分","v":"douban_score"}]}
        ],
        "dongman": [
            {"key":"type","name":"类型","value":[{"n":"全部","v":""},{"n":"少年","v":"少年"},{"n":"热血","v":"热血"},{"n":"科幻","v":"科幻"},{"n":"冒险","v":"冒险"},{"n":"动画","v":"动画"},{"n":"爱情","v":"爱情"},{"n":"奇幻","v":"奇幻"},{"n":"武侠","v":"武侠"},{"n":"悬疑","v":"悬疑"},{"n":"惊悚","v":"惊悚"},{"n":"剧情","v":"剧情"},{"n":"音乐","v":"音乐"},{"n":"恐怖","v":"恐怖"},{"n":"喜剧","v":"喜剧"},{"n":"儿童","v":"儿童"}]},
            {"key":"area","name":"地区","value":[{"n":"全部","v":""},{"n":"国产","v":"中国大陆"},{"n":"欧美","v":"欧美"},{"n":"日本","v":"日本"},{"n":"其他","v":"其他"}]},
            {"key":"year","name":"年代","value":[{"n":"全部","v":""},{"n":"2026","v":"2026"},{"n":"2025","v":"2025"},{"n":"2024","v":"2024"},{"n":"2023","v":"2023"},{"n":"2022","v":"2022"},{"n":"2021","v":"2021"},{"n":"2020","v":"2020"},{"n":"2019","v":"2019"},{"n":"2018","v":"2018"},{"n":"2017","v":"2017"},{"n":"2016","v":"2016"},{"n":"2015","v":"2015"},{"n":"2014","v":"2014"},{"n":"2013","v":"2013"},{"n":"2012","v":"2012"},{"n":"2011","v":"2011"},{"n":"2010","v":"2010"}]},
            {"key":"by","name":"排序","value":[{"n":"时间","v":"time"},{"n":"人气","v":"hits_week"},{"n":"评分","v":"douban_score"}]}
        ],
        "duanju": [
            {"key":"type","name":"类型","value":[{"n":"全部","v":""},{"n":"重生民国","v":"重生民国"},{"n":"穿越年代","v":"穿越年代"},{"n":"古装仙侠","v":"古装仙侠"},{"n":"AI漫剧","v":"AI漫剧"},{"n":"都市脑洞","v":"都市脑洞"},{"n":"现代言情","v":"现代言情"},{"n":"反转爽文","v":"反转爽文"},{"n":"女恋总裁","v":"女恋总裁"},{"n":"闪婚离婚","v":"闪婚离婚"}]},
            {"key":"area","name":"地区","value":[{"n":"全部","v":""},{"n":"中国大陆","v":"中国大陆"}]},
            {"key":"year","name":"年代","value":[{"n":"全部","v":""},{"n":"2026","v":"2026"},{"n":"2025","v":"2025"},{"n":"2024","v":"2024"},{"n":"2023","v":"2023"},{"n":"2022","v":"2022"},{"n":"2021","v":"2021"},{"n":"2020","v":"2020"},{"n":"2019","v":"2019"},{"n":"2018","v":"2018"},{"n":"2017","v":"2017"},{"n":"2016","v":"2016"},{"n":"2015","v":"2015"},{"n":"2014","v":"2014"},{"n":"2013","v":"2013"},{"n":"2012","v":"2012"},{"n":"2011","v":"2011"},{"n":"2010","v":"2010"}]},
            {"key":"by","name":"排序","value":[{"n":"综合排序","v":"time"},{"n":"热度最高","v":"hits_week"},{"n":"最新上线","v":"id"},{"n":"最好评","v":"douban_score"}]}
        ]
    }

    def getName(self):
        return "追影影院"

    def init(self, extend):
        pass

    def isVideoFormat(self, url):
        pass

    def manualVideoCheck(self):
        pass

    def homeContent(self, filter):
        classes = [
            {"type_id": "dianying", "type_name": "电影"},
            {"type_id": "dianshiju", "type_name": "电视剧"},
            {"type_id": "zongyi", "type_name": "综艺"},
            {"type_id": "dongman", "type_name": "动漫"},
            {"type_id": "duanju", "type_name": "短剧"}
        ]
        filters = {}
        for cls in classes:
            cid = cls["type_id"]
            if cid in self.static_filters:
                filters[cid] = self.static_filters[cid]
        return {'class': classes, 'filters': filters}

    def _fetch(self, url):
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return BeautifulSoup(resp.content, 'lxml')   # ← 改这里：text → content

    def _parse_home_list(self, soup):
        videos = []
        seen = set()
        for a in soup.select('a.card.js-card-item'):
            href = a.get('href', '')
            if not href.startswith('/video/'):
                continue
            vid = urljoin(xurl, href)
            if vid in seen:
                continue
            seen.add(vid)

            img = a.select_one('.card-cover img')
            title_alt = img.get('alt', '').strip() if img else ''
            title_tag = a.select_one('.card-title')
            title_from_tag = title_tag.get_text(strip=True) if title_tag else ''
            title = title_alt if title_alt else title_from_tag

            pic = img.get('src', '') if img else ''
            if pic.startswith('//'):
                pic = 'https:' + pic
            elif pic and not pic.startswith('http'):
                pic = urljoin(xurl, pic)

            status = a.select_one('.card-status')
            remark = status.get_text(strip=True) if status else ''

            if title:
                videos.append({
                    "vod_id": vid,
                    "vod_name": title,
                    "vod_pic": pic,
                    "vod_remarks": remark
                })
        return videos

    def homeVideoContent(self):
        return {'list': self._parse_home_list(self._fetch(xurl))}

    def categoryContent(self, cid, pg, filter, ext):
        page = int(pg) if pg else 1
        cateId = cid

        area = urllib.parse.quote(ext.get('area', '')) if ext else ''
        by = urllib.parse.quote(ext.get('by', '')) if ext else ''
        class_ = urllib.parse.quote(ext.get('type', '')) if ext else ''
        lang = urllib.parse.quote(ext.get('lang', '')) if ext else ''
        letter = urllib.parse.quote(ext.get('letter', '')) if ext else ''
        year = urllib.parse.quote(ext.get('year', '')) if ext else ''

        url = f"{xurl}/vodshow/{cateId}-{area}-{by}-{class_}-{lang}-{letter}---{page}---{year}.html"

        try:
            soup = self._fetch(url)
            videos = self._parse_home_list(soup)
        except Exception:
            videos = []

        return {
            'list': videos,
            'page': page,
            'pagecount': 9999,
            'limit': 30,
            'total': 999999
        }

    def detailContent(self, ids):
        did = ids[0]
        if not did.startswith('http'):
            did = urljoin(xurl, did)
        soup = self._fetch(did)

        vod = {"vod_id": did}
        t = soup.select_one('h1.detail-title') or soup.select_one('h1')
        vod["vod_name"] = t.get_text(strip=True) if t else ''

        img = soup.select_one('.detail-poster-wrap img') or soup.select_one('img.detail-poster')
        if img:
            pic = img.get('src', '')
            if pic.startswith('//'):
                pic = 'https:' + pic
            elif pic and not pic.startswith('http'):
                pic = urljoin(xurl, pic)
            vod["vod_pic"] = pic

        desc = soup.select_one('.synopsis-text')
        if desc:
            vod["vod_content"] = desc.get_text(strip=True)

        year = soup.select_one('.detail-year')
        if year:
            m = re.search(r'(\d{4})', year.get_text(strip=True))
            if m:
                vod["vod_year"] = m.group(1)

        badge = soup.select_one('.poster-badge')
        if badge:
            vod["vod_remarks"] = badge.get_text(strip=True)

        for line in soup.select('.cast-info .actor-line'):
            lbl = line.select_one('.label')
            val = line.select_one('.val')
            if lbl and val:
                key = lbl.get_text(strip=True).replace(':', '').replace('：', '')
                value = val.get_text(strip=True)
                if key == '导演':
                    vod['vod_director'] = value
                elif key == '主演':
                    vod['vod_actor'] = value

        for item in soup.select('.hero-meta-matrix .matrix-item'):
            lbl = item.select_one('.m-lbl')
            val = item.select_one('.m-val')
            if lbl and val:
                k = lbl.get_text(strip=True)
                v = val.get_text(strip=True)
                if k == '类型':
                    vod['type_name'] = v
                elif k in ('制片国家/地区', '地区'):
                    vod['vod_area'] = v

        ktabs, klists = [], []
        seen = set()
        tabs = soup.select('.source-tab')
        lists = soup.select('.ep-square-list')
        for i, tab in enumerate(tabs):
            if i >= len(lists):
                break
            name = tab.select_one('.tab-name')
            line_name = name.get_text(strip=True) if name else f'线路{i+1}'
            if line_name in seen:
                continue
            eps = []
            for a in lists[i].select('a.ep-item-square'):
                ep_name = a.get('data-name', '').strip()
                if not ep_name:
                    ep_name = a.get_text(strip=True)
                href = a.get('href', '')
                if ep_name and href:
                    eps.append(f'{ep_name}${href}')
            if eps:
                seen.add(line_name)
                ktabs.append(line_name)
                klists.append('#'.join(eps))
        vod["vod_play_from"] = '$$$'.join(ktabs) if ktabs else ''
        vod["vod_play_url"] = '$$$'.join(klists) if klists else ''

        for f in ['vod_name', 'vod_pic', 'type_name', 'vod_area', 'vod_year',
                  'vod_remarks', 'vod_director', 'vod_actor', 'vod_content',
                  'vod_play_from', 'vod_play_url']:
            if f not in vod:
                vod[f] = ''
        return {'list': [vod]}

    def playerContent(self, flag, id, vipFlags):
        try:
            play_url = id if id.startswith('http') else urljoin(xurl, id)
            if any(ext in play_url.lower() for ext in ['.m3u8', '.mp4', '.flv']):
                return {"parse": 0, "url": play_url, "header": json.dumps(headers)}

            resp = requests.get(play_url, headers=headers, timeout=10)
            resp.encoding = resp.apparent_encoding or 'utf-8'
            html = resp.text

            m = re.search(r'MAC_PLAY_CONFIG\s*=\s*(\{[\s\S]*?\});', html)
            if m:
                raw = m.group(1)
                cfg = json.loads(re.sub(r'([{,]\s*)([a-zA-Z_]\w*)\s*:', r'\1"\2":', raw))
                base_key = cfg.get('baseKey', '')
                req_url = cfg.get('requestUrl', '')
                if base_key and req_url:
                    ts = str(int(time.time()))
                    ua = headers.get('User-Agent', '')
                    token = hashlib.md5((base_key + ts + ua).encode()).hexdigest()
                    api = urljoin(xurl, '/player_api.php')
                    r = requests.post(api, data={'url': req_url, 'timestamp': ts, 'token': token},
                                      headers=headers, timeout=15)
                    data = r.json()
                    if not data.get('error') and data.get('data'):
                        enc = data['data']
                        rev = enc[::-1]
                        pad = 0
                        while rev.startswith('='):
                            rev = rev[1:]
                            pad += 1
                        rev += '=' * pad
                        dec = json.loads(urllib.parse.unquote(base64.b64decode(rev).decode('latin-1')))
                        real = dec.get('jmurl', '')
                        if real:
                            is_direct = any(ext in real.lower() for ext in ['.m3u8', '.mp4', '.flv'])
                            return {"parse": 0 if is_direct else 1, "url": real, "header": json.dumps(headers)}

            m = re.search(r'var\s+player_\w+\s*=\s*(\{.*?\})\s*;', html, re.DOTALL)
            if m:
                try:
                    d = json.loads(re.sub(r',\s*}', '}', m.group(1)))
                    u = d.get('url', '')
                    if u:
                        return {"parse": 0 if any(ext in u.lower() for ext in ['.m3u8', '.mp4']) else 1,
                                "url": u, "header": json.dumps(headers)}
                except:
                    pass

            m = re.search(r'["\']url["\']\s*:\s*["\'](https?://[^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', html, re.I)
            if m:
                return {"parse": 0, "url": m.group(1), "header": json.dumps(headers)}

            soup = BeautifulSoup(html, 'lxml')
            iframe = soup.select_one('iframe')
            if iframe and iframe.get('src'):
                return {"parse": 1, "url": urljoin(play_url, iframe.get('src')), "header": json.dumps(headers)}

            return {"parse": 1, "url": play_url, "header": json.dumps(headers)}

        except Exception as e:
            return {"parse": 1, "url": urljoin(xurl, id), "header": json.dumps(headers)}

    def searchContent(self, key, quick, page='1'):
        page = int(page) if page else 1
        url = f"{xurl}/vod/search/wd/{urllib.parse.quote(key, safe='')}/page/{page}.html"
        try:
            soup = self._fetch(url)
            videos = self._parse_search_list(soup)
        except:
            videos = []
        return {
            'list': videos,
            'page': page,
            'pagecount': 60,
            'limit': 30,
            'total': 999999
        }

    def _parse_search_list(self, soup):
        videos = []
        seen = set()
        for card in soup.select('div.search-list-card'):
            a = card.select_one('a.list-card-thumb')
            if not a:
                continue
            href = a.get('href', '')
            if not href.startswith('/video/'):
                continue
            vid = urljoin(xurl, href)
            if vid in seen:
                continue
            seen.add(vid)

            img = a.select_one('img')
            title_alt = img.get('alt', '').strip() if img else ''
            title_tag = card.select_one('h4.list-title a')
            title_from_tag = title_tag.get_text(strip=True) if title_tag else ''
            title = title_alt if title_alt else title_from_tag

            pic = img.get('src', '') if img else ''
            if pic.startswith('//'):
                pic = 'https:' + pic
            elif pic and not pic.startswith('http'):
                pic = urljoin(xurl, pic)

            remark_tag = a.select_one('span.list-thumb-remark')
            remark = remark_tag.get_text(strip=True) if remark_tag else ''

            if title:
                videos.append({
                    "vod_id": vid,
                    "vod_name": title,
                    "vod_pic": pic,
                    "vod_remarks": remark
                })
        return videos

def get_spider():
    return Spider()