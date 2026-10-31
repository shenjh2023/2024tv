import requests
from bs4 import BeautifulSoup
import re
import sys
import json
import urllib.parse
from base.spider import Spider
from urllib.parse import urljoin

sys.path.append('..')

xurl = "https://ijianpin.com"
headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 13; M2102J2SC Build/TKQ1.221114.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/144.0.7559.31 Mobile Safari/537.36',
    'Referer': xurl,
}

AREA_FILTER = {"key": "area", "name": "地区", "value": [{"n":"全部","v":""},{"n":"大陆","v":"中国大陆"},{"n":"香港","v":"中国香港"},{"n":"台湾","v":"中国台湾"},{"n":"美国","v":"美国"},{"n":"日本","v":"日本"},{"n":"韩国","v":"韩国"},{"n":"德国","v":"德国"},{"n":"泰国","v":"泰国"},{"n":"英国","v":"英国"},{"n":"法国","v":"法国"},{"n":"意大利","v":"意大利"},{"n":"西班牙","v":"西班牙"}]}
YEAR_FILTER = {"key": "year", "name": "年代", "value": [{"n":"全部","v":""},{"n":"2026","v":"2026"},{"n":"2025","v":"2025"},{"n":"2024","v":"2024"},{"n":"2023","v":"2023"},{"n":"2022","v":"2022"},{"n":"2021","v":"2021"},{"n":"2020","v":"2020"},{"n":"2019","v":"2019"},{"n":"2018","v":"2018"},{"n":"2017","v":"2017"},{"n":"2016","v":"2016"},{"n":"2015","v":"2015"},{"n":"2014","v":"2014"},{"n":"2013","v":"2013"},{"n":"2012","v":"2012"},{"n":"2011","v":"2011"},{"n":"2010","v":"2010"}]}
LANG_FILTER = {"key": "lang", "name": "语言", "value": [{"n":"全部","v":""},{"n":"国语","v":"国语"},{"n":"英语","v":"英语"},{"n":"粤语","v":"粤语"},{"n":"韩语","v":"韩语"},{"n":"日语","v":"日语"},{"n":"法语","v":"法语"},{"n":"德语","v":"德语"},{"n":"其它","v":"其它"}]}
LETTER_FILTER = {"key": "letter", "name": "字母", "value": [{"n":"全部","v":""},{"n":"A","v":"A"},{"n":"B","v":"B"},{"n":"C","v":"C"},{"n":"D","v":"D"},{"n":"E","v":"E"},{"n":"F","v":"F"},{"n":"G","v":"G"},{"n":"H","v":"H"},{"n":"I","v":"I"},{"n":"J","v":"J"},{"n":"K","v":"K"},{"n":"L","v":"L"},{"n":"M","v":"M"},{"n":"N","v":"N"},{"n":"O","v":"O"},{"n":"P","v":"P"},{"n":"Q","v":"Q"},{"n":"R","v":"R"},{"n":"S","v":"S"},{"n":"T","v":"T"},{"n":"U","v":"U"},{"n":"V","v":"V"},{"n":"W","v":"W"},{"n":"X","v":"X"},{"n":"Y","v":"Y"},{"n":"Z","v":"Z"},{"n":"0-9","v":"0-9"}]}
BY_FILTER = {"key": "by", "name": "排序", "value": [{"n":"时间排序","v":"time"},{"n":"人气排序","v":"hits"},{"n":"评分排序","v":"score"}]}

class Spider(Spider):
    def getName(self):
        return "努努影院"

    def init(self, extend):
        pass

    def _sc(self, soup, selector, text):
        for elem in soup.select(selector):
            if text in elem.get_text():
                return elem
        return None

    def homeContent(self, filter):
        class_items = [
            {"type_id": "dianying", "type_name": "电影"},
            {"type_id": "dsj", "type_name": "剧集"},
            {"type_id": "dongman", "type_name": "动漫"},
            {"type_id": "zongyi", "type_name": "综艺"},
            {"type_id": "shuangwenduanju", "type_name": "爽文短剧"},
            {"type_id": "4kdianying", "type_name": "4k电影"},
            {"type_id": "tiyusaishi", "type_name": "体育赛事"}
        ]
        static_filters = {
            "dianying": [
                {"key": "cateId", "name": "类型", "value": [{"n":"全部","v":""},{"n":"喜剧片","v":"xijupian"},{"n":"动作片","v":"dongzuopian"},{"n":"爱情片","v":"aiqingpian"},{"n":"科幻片","v":"kehuanpian"},{"n":"恐怖片","v":"kongbupian"},{"n":"剧情片","v":"juqingpian"},{"n":"战争片","v":"zhanzhengpian"},{"n":"悬疑片","v":"xuanyipian"},{"n":"犯罪片","v":"fanzuipian"}]},
                {"key": "class", "name": "剧情", "value": [{"n":"全部","v":""},{"n":"喜剧","v":"喜剧"},{"n":"爱情","v":"爱情"},{"n":"恐怖","v":"恐怖"},{"n":"动作","v":"动作"},{"n":"科幻","v":"科幻"},{"n":"剧情","v":"剧情"},{"n":"战争","v":"战争"},{"n":"警匪","v":"警匪"},{"n":"犯罪","v":"犯罪"},{"n":"动画","v":"动画"},{"n":"奇幻","v":"奇幻"},{"n":"武侠","v":"武侠"},{"n":"冒险","v":"冒险"},{"n":"枪战","v":"枪战"},{"n":"悬疑","v":"悬疑"},{"n":"惊悚","v":"惊悚"},{"n":"经典","v":"经典"},{"n":"青春","v":"青春"},{"n":"文艺","v":"文艺"},{"n":"微电影","v":"微电影"},{"n":"古装","v":"古装"},{"n":"历史","v":"历史"},{"n":"运动","v":"运动"},{"n":"农村","v":"农村"},{"n":"儿童","v":"儿童"},{"n":"网络电影","v":"网络电影"}]},
                AREA_FILTER, YEAR_FILTER, LANG_FILTER, LETTER_FILTER, BY_FILTER
            ],
            "dsj": [
                {"key": "cateId", "name": "类型", "value": [{"n":"全部","v":""},{"n":"国产剧","v":"guochanju"},{"n":"欧美剧","v":"oumeiju"},{"n":"日剧","v":"riju"},{"n":"韩剧","v":"hanju"},{"n":"港剧","v":"gangju"},{"n":"台剧","v":"taiju"},{"n":"泰国剧","v":"taiguoju"},{"n":"海外剧","v":"haiwaiju"}]},
                {"key": "class", "name": "剧情", "value": [{"n":"全部","v":""},{"n":"古装","v":"古装"},{"n":"战争","v":"战争"},{"n":"青春偶像","v":"青春偶像"},{"n":"喜剧","v":"喜剧"},{"n":"家庭","v":"家庭"},{"n":"犯罪","v":"犯罪"},{"n":"动作","v":"动作"},{"n":"奇幻","v":"奇幻"},{"n":"剧情","v":"剧情"},{"n":"历史","v":"历史"},{"n":"经典","v":"经典"},{"n":"乡村","v":"乡村"},{"n":"情景","v":"情景"},{"n":"商战","v":"商战"},{"n":"网剧","v":"网剧"},{"n":"其他","v":"其他"}]},
                AREA_FILTER, YEAR_FILTER, LANG_FILTER, LETTER_FILTER, BY_FILTER
            ],
            "dongman": [
                {"key": "cateId", "name": "类型", "value": [{"n":"全部","v":""},{"n":"国产动漫","v":"guochandongman"},{"n":"日韩动漫","v":"rihandongman"},{"n":"欧美动漫","v":"oumeidongman"},{"n":"港台动漫","v":"gangtaidongman"},{"n":"海外动漫","v":"haiwaidongman"}]},
                {"key": "class", "name": "剧情", "value": [{"n":"全部","v":""},{"n":"情感","v":"情感"},{"n":"科幻","v":"科幻"},{"n":"热血","v":"热血"},{"n":"推理","v":"推理"},{"n":"搞笑","v":"搞笑"},{"n":"冒险","v":"冒险"},{"n":"萝莉","v":"萝莉"},{"n":"校园","v":"校园"},{"n":"动作","v":"动作"},{"n":"机战","v":"机战"},{"n":"运动","v":"运动"},{"n":"战争","v":"战争"},{"n":"少年","v":"少年"},{"n":"少女","v":"少女"},{"n":"社会","v":"社会"},{"n":"原创","v":"原创"},{"n":"亲子","v":"亲子"},{"n":"益智","v":"益智"},{"n":"励志","v":"励志"},{"n":"其他","v":"其他"}]},
                AREA_FILTER, YEAR_FILTER, LANG_FILTER, LETTER_FILTER, BY_FILTER
            ],
            "zongyi": [
                {"key": "cateId", "name": "类型", "value": [{"n":"全部","v":""},{"n":"国产综艺","v":"guochanzongyi"},{"n":"日韩综艺","v":"rihanzongyi"},{"n":"港台综艺","v":"gangtaizongyi"},{"n":"欧美综艺","v":"oumeizongyi"}]},
                {"key": "class", "name": "剧情", "value": [{"n":"全部","v":""},{"n":"选秀","v":"选秀"},{"n":"情感","v":"情感"},{"n":"访谈","v":"访谈"},{"n":"播报","v":"播报"},{"n":"旅游","v":"旅游"},{"n":"音乐","v":"音乐"},{"n":"美食","v":"美食"},{"n":"纪实","v":"纪实"},{"n":"曲艺","v":"曲艺"},{"n":"生活","v":"生活"},{"n":"游戏互动","v":"游戏互动"},{"n":"财经","v":"财经"},{"n":"求职","v":"求职"}]},
                AREA_FILTER, YEAR_FILTER, LANG_FILTER, LETTER_FILTER, BY_FILTER
            ],
            "shuangwenduanju": [
                {"key": "cateId", "name": "类型", "value": [{"n":"全部","v":""},{"n":"有声动漫","v":"youshengdongman"},{"n":"女频恋爱","v":"nvpinlianai"},{"n":"反转爽剧","v":"fanzhuanshuangju"},{"n":"脑洞悬疑","v":"naodongxuanyi"},{"n":"年代穿越","v":"niandaichuanyue"},{"n":"古装仙侠","v":"guzhuangxianxia"},{"n":"现代都市","v":"xiandaidushi"},{"n":"爽文短剧","v":"shuangwenduanju"}]},
                {"key": "class", "name": "剧情", "value": [{"n":"全部","v":""},{"n":"都市","v":"都市"},{"n":"现代","v":"现代"},{"n":"穿越","v":"穿越"},{"n":"年代","v":"年代"},{"n":"言情","v":"言情"},{"n":"爱情","v":"爱情"},{"n":"重生","v":"重生"},{"n":"总裁","v":"总裁"},{"n":"反转","v":"反转"},{"n":"剧情","v":"剧情"},{"n":"古装","v":"古装"},{"n":"仙侠","v":"仙侠"},{"n":"民国","v":"民国"},{"n":"闪婚","v":"闪婚"},{"n":"离婚","v":"离婚"},{"n":"脑洞","v":"脑洞"},{"n":"其他","v":"其他"}]},
                AREA_FILTER, YEAR_FILTER, LANG_FILTER, LETTER_FILTER, BY_FILTER
            ],
            "4kdianying": [
                YEAR_FILTER, LANG_FILTER, LETTER_FILTER, BY_FILTER
            ],
            "tiyusaishi": [
                YEAR_FILTER, LETTER_FILTER, BY_FILTER
            ]
        }
        return {
            "class": class_items,
            "filters": static_filters
        }

    def _fetch_html(self, url):
        resp = requests.get(url, headers=headers, timeout=10)
        encoding = resp.apparent_encoding or 'utf-8'
        if encoding.lower() == 'gb2312':
            encoding = 'gbk'
        resp.encoding = encoding
        return resp.text

    def _get_soup(self, url):
        return BeautifulSoup(self._fetch_html(url), 'lxml')

    def _parse_video_items(self, soup):
        videos = []
        seen_ids = set()
        for a_tag in soup.select('a[href^="/voddetail/"]'):
            href = a_tag.get('href')
            if not href:
                continue
            vod_id = urljoin(xurl, href)
            if vod_id in seen_ids:
                continue
            seen_ids.add(vod_id)

            title = a_tag.get('title', '').strip()
            if not title:
                title = a_tag.get_text(strip=True)
            if not title:
                img = a_tag.select_one('img')
                if img:
                    title = img.get('alt', '').strip()
            if not title:
                continue

            pic = a_tag.get('data-src') or a_tag.get('data-original') or a_tag.get('src', '')
            if not pic:
                img = a_tag.select_one('img')
                if img:
                    pic = img.get('data-src') or img.get('data-original') or img.get('src', '')
            if pic.startswith('//'):
                pic = 'https:' + pic
            elif pic and not pic.startswith('http'):
                pic = urljoin(xurl, pic)

            remark_span = a_tag.select_one('.module-item-note')
            remark = remark_span.get_text(strip=True) if remark_span else ''

            videos.append({
                "vod_id": vod_id,
                "vod_name": title,
                "vod_pic": pic,
                "vod_remarks": remark
            })
        return videos

    def homeVideoContent(self):
        return {'list': self._parse_video_items(self._get_soup(xurl))}

    def categoryContent(self, cid, pg, filter, ext):
        page = int(pg) if pg else 1
        ext = ext or {}
        if 'cateId' in ext:
            cateId = str(ext['cateId'])
        else:
            cateId = str(cid)
        catePg = page

        area = urllib.parse.quote(ext.get('area', ''), safe='')
        by = urllib.parse.quote(ext.get('by', ''), safe='')
        class_ = urllib.parse.quote(ext.get('class', ''), safe='')
        lang = urllib.parse.quote(ext.get('lang', ''), safe='')
        letter = urllib.parse.quote(ext.get('letter', ''), safe='')
        year = urllib.parse.quote(ext.get('year', ''), safe='')

        url = f"{xurl}/vodshow/{cateId}-{area}-{by}-{class_}-{lang}-{letter}---{catePg}---{year}/"
        soup = self._get_soup(url)
        videos = self._parse_video_items(soup)
        return {
            'list': videos,
            'page': page,
            'pagecount': 9999,
            'limit': 30,
            'total': 999999
        }

    def detailContent(self, ids):
        did = ids[0]
        if 'http' not in did:
            did = xurl + did
        soup = BeautifulSoup(requests.get(url=did, headers=headers).text, "lxml")

        vod = {}
        vod["vod_id"] = did
        vod["vod_name"] = soup.select_one('h1').get_text(strip=True) if soup.select_one('h1') else ''
        img = soup.select_one('.module-info-poster img') or soup.select_one('.module-item-pic img')
        if img:
            pic = img.get('data-original', '') or img.get('data-src', '') or img.get('src', '')
            if pic.startswith('//'):
                pic = 'https:' + pic
            elif pic and not pic.startswith('http'):
                pic = urljoin(xurl, pic)
            vod["vod_pic"] = pic
        else:
            vod["vod_pic"] = ''
            
        year_tags = soup.select('.module-info-tag-link a')
        if len(year_tags) > 0:
            vod["vod_year"] = year_tags[0].get_text(strip=True)
        if len(year_tags) > 1:
            vod["vod_area"] = year_tags[1].get_text(strip=True)
        if len(year_tags) > 2:
            vod["type_name"] = '/'.join([a.get_text(strip=True) for a in year_tags[2:]])
        elem_update = self._sc(soup, '.module-info-item', '更新')
        vod["vod_remarks"] = elem_update.get_text().replace('更新：', '').strip() if elem_update else ''
        elem_director = self._sc(soup, '.module-info-item', '导演')
        vod["vod_director"] = elem_director.get_text().replace('导演：', '').replace('/', ' ').strip() if elem_director else ''
        elem_actor = self._sc(soup, '.module-info-item', '主演')
        vod["vod_actor"] = elem_actor.get_text().replace('主演：', '').replace('/', ' ').strip() if elem_actor else ''
        elem_intro = soup.select_one('.module-info-introduction-content')
        if elem_intro:
            p = elem_intro.select_one('p')
            vod["vod_content"] = p.get_text(strip=True) if p else elem_intro.get_text(strip=True)
        else:
            vod["vod_content"] = ''

        ktabs = []
        klists = []
        seen_lines = set()
        tab_items = soup.select('.module-tab-items-box .module-tab-item')
        playlist_containers = soup.select('.module-play-list-content')

        for idx, tab in enumerate(tab_items):
            if idx >= len(playlist_containers):
                break
            tab_title = tab.get('data-dropdown-value', '')
            if not tab_title:
                span = tab.select_one('span')
                if span:
                    tab_title = span.get_text(strip=True)
            if not tab_title:
                tab_title = f'线路{idx + 1}'
            tab_title = re.sub(r'\s*\d+$', '', tab_title).strip()
            if tab_title in ['蓝光极速', '蓝光线路', '相关推荐'] or tab_title in seen_lines:
                continue
            episode_links = playlist_containers[idx].select('.module-play-list-link')
            klist = []
            for link in episode_links:
                span = link.select_one('span')
                ep_name = span.get_text(strip=True) if span else link.get_text(strip=True)
                ep_url = link.get('href', '')
                if not ep_name or not ep_url or ep_name in ['1080P', 'дрр滈凊']:
                    continue
                klist.append(f'{ep_name}${ep_url}')
            if klist:
                seen_lines.add(tab_title)
                ktabs.append(tab_title)
                klists.append('#'.join(klist))

        vod["vod_play_from"] = '$$$'.join(ktabs)
        vod["vod_play_url"] = '$$$'.join(klists)

        return {'list': [vod]}

    def playerContent(self, flag, id, vipFlags):
        try:
            play_url = id if id.startswith(('http://', 'https://')) else urljoin(xurl, id)
            html = self._fetch_html(play_url)
            video_url = ''
            m = re.search(r'var\s+player_\w+\s*=\s*(\{.*?\})\s*;?\s*</script>', html, re.DOTALL)
            if m:
                try:
                    json_str = re.sub(r',\s*}', '}', m.group(1))
                    data = json.loads(json_str)
                    enc = data.get('url', '')
                    if enc:
                        video_url = enc
                except:
                    pass
            if not video_url:
                m = re.search(r'["\']url["\']\s*:\s*["\'](https?://[^"\']+\.(?:m3u8|mp4|mkv|flv|ts)[^"\']*)["\']', html, re.I)
                if m:
                    video_url = m.group(1)
            if not video_url:
                m = re.search(r'var\s+now\s*=\s*["\'](https?://[^"\']+)["\']', html)
                if m:
                    video_url = m.group(1)
            if video_url:
                parse = 0 if re.search(r'\.(m3u8|mp4|mkv|flv|ts)(\?|$)', video_url, re.I) else 1
                if parse:
                    video_url = play_url
            else:
                parse = 1
                video_url = play_url
            return {"parse": parse, "playUrl": "", "url": video_url, "header": json.dumps(headers)}
        except Exception as e:
            print(f"player error: {e}")
            return {"parse": 1, "playUrl": "", "url": urljoin(xurl, id), "header": json.dumps(headers)}

    def searchContent(self, key, quick, page='1'):
        page = int(page) if page else 1
        encoded_key = urllib.parse.quote(key, safe='')
        url = f"{xurl}/vodsearch/{encoded_key}----------{page}---/"
        soup = self._get_soup(url)
        videos = self._parse_video_items(soup)
        return {
            'list': videos,
            'page': page,
            'pagecount': 60,
            'limit': 30,
            'total': 999999
        }
