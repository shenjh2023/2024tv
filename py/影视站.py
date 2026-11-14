#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# 4K影视站 | www.4kdyw.com | TVBox / dr_py 影视源
# -----------------------------------------------------------------------------
# 站点: Nuxt SSR, 官方 JSON 接口前缀 /api/show/v2
#   分类列表 : GET /api/show/v2/type/{typeId}/{page}
#   搜索     : GET /api/show/v2/search/{关键词}/{page}
#   详情     : GET /api/show/v2/vod/{vodId}
#   分类树   : GET /api/show/v2/cate/{cateId}   (cateId: 1电影 2电视剧 3动漫 4综艺)
#   热播     : GET /api/show/v2/vodhot
# 播放: 第三方 m3u8 直链(parse=0), 线路名取 vod_play[].collectSource.webName
# 支持: 分类翻页 / 搜索翻页 / 多线路 / init 可传备用域名
# 独立自测: python 4K影视站.py
# =============================================================================
import json
import time
import requests
from urllib.parse import quote

try:
    from base.spider import Spider  # dr_py 运行环境
except Exception:  # 独立运行 / 非 dr_py 环境
    class Spider(object):
        pass


class Spider(Spider):
    HOST = 'https://www.4kdyw.com'
    API = HOST + '/api/show/v2'
    UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')

    # 静态分类树兜底(动态获取失败时使用): (cateId, 大类名, [(子类typeId, 子类名), ...])
    FALLBACK_CLASS = [
        (1, '电影', [(1, '动作片'), (2, '喜剧片'), (3, '爱情片'), (4, '科幻片'),
                     (5, '恐怖片'), (6, '剧情片'), (7, '战争片')]),
        (2, '电视剧', [(8, '国产剧'), (9, '香港剧'), (10, '韩国剧'), (11, '欧美剧'),
                       (12, '台湾剧'), (13, '日本剧'), (14, '海外剧'), (15, '泰国剧')]),
        (3, '动漫', [(16, '国产动漫'), (17, '日韩动漫'), (18, '欧美动漫'),
                     (19, '港台动漫'), (20, '海外动漫')]),
        (4, '综艺', [(21, '大陆综艺'), (22, '港台综艺'), (23, '日韩综艺'), (24, '欧美综艺')]),
    ]

    _session = None

    def init(self, extend='', config=None):
        # extend 可传备用域名(json 或纯字符串), 如 {"host":"https://xxx.com"} 或 https://xxx.com
        host = ''
        try:
            raw = str(extend or '').strip()
            if raw:
                try:
                    ext = json.loads(raw)
                    if isinstance(ext, dict):
                        host = str(ext.get('host') or ext.get('extend') or '').strip()
                    elif isinstance(ext, str):
                        host = ext.strip()
                except Exception:
                    host = raw
        except Exception:
            pass
        if host:
            host = host.rstrip('/')
            if not host.startswith('http'):
                host = 'https://' + host
            self.HOST = host
            self.API = host + '/api/show/v2'

    def getName(self):
        return '4K影视站'

    def isVideoUrl(self):
        return False

    # ---------------- 基础请求 ----------------
    def _get_session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': self.UA,
                'Referer': self.HOST + '/',
                'Accept': 'application/json, text/plain, */*',
            })
        return self._session

    def get_json(self, url, retries=1):
        session = self._get_session()
        err = None
        for i in range(retries + 1):
            try:
                r = session.get(url, timeout=(5, 12))
                if r.status_code == 200:
                    return r.json()
                err = 'HTTP %s' % r.status_code
            except Exception as e:
                err = e
            time.sleep(0.6 * (i + 1))
        raise Exception('request fail: %s -> %s' % (url, err))

    @staticmethod
    def _item(v):
        """列表项 -> TVBox vod 结构"""
        pic = (v.get('vodPic') or '').strip()
        if pic and not pic.startswith('http'):
            pic = 'https://' + pic.lstrip('/')
        remarks = (v.get('vodLastRemarks') or '').strip()
        if not remarks:
            remarks = (v.get('vodState') or '').strip()
        return {
            'vod_id': str(v.get('vodId') or ''),
            'vod_name': v.get('vodName') or '',
            'vod_pic': pic,
            'vod_remarks': remarks,
        }

    @staticmethod
    def _pick_list(data):
        """兼容 vod_recent / vods 两种键名, data 可能为数组或对象"""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get('vod_recent') or data.get('vods') or []
        return []

    # ---------------- 首页 ----------------
    def homeContent(self, filter=None):
        result = {'class': [], 'list': []}
        classes = []
        try:
            for cate_id in (1, 2, 3, 4):
                res = self.get_json('%s/cate/%s' % (self.API, cate_id))
                data = (res or {}).get('data') or {}
                for t in data.get('type') or []:
                    if t.get('typeId'):
                        classes.append({'type_id': str(t['typeId']),
                                        'type_name': t.get('typeName') or ''})
        except Exception:
            classes = []
        if not classes:
            for _, _, subs in self.FALLBACK_CLASS:
                for tid, name in subs:
                    classes.append({'type_id': str(tid), 'type_name': name})
        result['class'] = classes
        try:
            res = self.get_json('%s/vodhot' % self.API)
            result['list'] = [self._item(v) for v in self._pick_list((res or {}).get('data'))]
        except Exception:
            pass
        return result

    def homeVideoContent(self):
        try:
            res = self.get_json('%s/vodhot' % self.API)
            return {'list': [self._item(v) for v in self._pick_list((res or {}).get('data'))]}
        except Exception:
            return {'list': []}

    # ---------------- 分类 ----------------
    def categoryContent(self, tid, pg=1, filter=None, extend=None):
        try:
            page = int(str(pg or '1').strip() or 1)
        except Exception:
            page = 1
        tid = str(tid).strip()
        result = {'list': [], 'page': page, 'pagecount': 1, 'limit': 18, 'total': 0}
        try:
            res = self.get_json('%s/type/%s/%s' % (self.API, tid, page))
            data = (res or {}).get('data') or {}
            vods = data.get('vod_recent') or data.get('vods') or []
            result['list'] = [self._item(v) for v in vods]
            try:
                result['total'] = int(data.get('total') or 0)
            except Exception:
                result['total'] = len(vods)
            try:
                result['pagecount'] = int(data.get('total_page') or 1)
            except Exception:
                result['pagecount'] = 1
            try:
                result['limit'] = int(data.get('per_page') or 18)
            except Exception:
                pass
        except Exception:
            pass
        return result

    # ---------------- 详情 ----------------
    def detailContent(self, ids):
        vid = str(ids[0]).strip()
        res = self.get_json('%s/vod/%s' % (self.API, vid))
        data = (res or {}).get('data') or {}
        play_from = []
        play_url = []
        blurb = ''
        seen = {}
        for i, p in enumerate(data.get('vod_play') or []):
            src = p.get('collectSource') or {}
            name = (src.get('webName') or src.get('collectName') or '').strip()
            if not name:
                name = '线路%d' % (i + 1)
            if name in seen:
                seen[name] += 1
                name = '%s%d' % (name, seen[name])
            else:
                seen[name] = 1
            url = (p.get('vodPlayUrl') or '').strip()
            if not url:
                continue
            if not blurb:
                blurb = (p.get('vodBlurb') or p.get('vodContent') or '').strip()
            play_from.append(name)
            play_url.append(url)
        pic = (data.get('vodPic') or '').strip()
        if pic and not pic.startswith('http'):
            pic = 'https://' + pic.lstrip('/')
        vod = {
            'vod_id': vid,
            'vod_name': data.get('vodName') or '',
            'vod_pic': pic,
            'vod_remarks': data.get('vodLastRemarks') or '',
            'vod_year': data.get('vodYear') or '',
            'vod_area': data.get('vodArea') or '',
            'vod_actor': data.get('vodActor') or '',
            'vod_director': data.get('vodDirector') or '',
            'vod_lang': data.get('vodLang') or '',
            'vod_content': blurb,
            'vod_play_from': '$$$'.join(play_from),
            'vod_play_url': '$$$'.join(play_url),
        }
        return {'list': [vod]}

    # ---------------- 搜索 ----------------
    def _search(self, key, pg):
        url = '%s/search/%s/%s' % (self.API, quote(str(key or '').strip(), safe=''), pg)
        res = self.get_json(url)
        data = (res or {}).get('data') or {}
        vods = data.get('vods') or data.get('vod_recent') or []
        try:
            page = int(str(pg or '1'))
        except Exception:
            page = 1
        try:
            pagecount = int(data.get('total_page') or 1)
        except Exception:
            pagecount = 1
        return {
            'list': [self._item(v) for v in vods],
            'page': page,
            'pagecount': pagecount,
            'total': data.get('total') or len(vods),
        }

    def searchContent(self, key, quick=None, pg='1'):
        try:
            return self._search(key, pg)
        except Exception:
            return {'list': []}

    def searchContentPage(self, key, quick=None, pg='1'):
        try:
            return self._search(key, pg)
        except Exception:
            return {'list': []}

    # ---------------- 播放 ----------------
    def playerContent(self, flag, id, vipFlags=None):
        return {
            'parse': 0,
            'playUrl': '',
            'url': str(id).strip(),
            'flag': flag,
            'header': {
                'User-Agent': self.UA,
                'Referer': self.HOST + '/',
            },
        }


# ============================ 独立自测 ============================
if __name__ == '__main__':
    try:
        import sys
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    def show(title, obj, max_len=600):
        txt = json.dumps(obj, ensure_ascii=False, indent=None)
        if len(txt) > max_len:
            txt = txt[:max_len] + ' ...'
        print('[%s] %s' % (title, txt))

    sp = Spider()
    sp.init()

    home = sp.homeContent(False)
    print('分类数: %d -> %s' % (len(home['class']),
          ' | '.join('%s:%s' % (c['type_id'], c['type_name']) for c in home['class'])))
    print('首页推荐: %d 部, 第1部: %s' % (len(home['list']),
          home['list'][0]['vod_name'] if home['list'] else '无'))

    cat = sp.categoryContent('1', '1')
    print('分类[动作片]第1页: %d 部, 总数=%s, 总页=%s, 第1部: %s (%s)' % (
        len(cat['list']), cat['total'], cat['pagecount'],
        cat['list'][0]['vod_name'] if cat['list'] else '无',
        cat['list'][0]['vod_remarks'] if cat['list'] else ''))
    show('分类第1部海报', cat['list'][0]['vod_pic'] if cat['list'] else '')

    cat2 = sp.categoryContent('1', '2')
    print('分类[动作片]第2页: %d 部, 第1部: %s' % (len(cat2['list']),
          cat2['list'][0]['vod_name'] if cat2['list'] else '无'))

    search = sp.searchContent('地理', False)
    print('搜索[地理]: %d 条, 第1条: %s' % (len(search['list']),
          search['list'][0]['vod_name'] if search['list'] else '无'))

    first_id = (cat['list'][0]['vod_id'] if cat['list'] else '31505')
    detail = sp.detailContent([first_id])
    vod = detail['list'][0]
    print('详情[%s]: %s | %s | %s | 线路: %s' % (
        first_id, vod['vod_name'], vod['vod_remarks'], vod['vod_area'], vod['vod_play_from']))
    show('简介', vod['vod_content'], 160)
    urls = vod['vod_play_url'].split('$$$')
    first_flag = vod['vod_play_from'].split('$$$')[0]
    first_ep = urls[0].split('#')[0] if urls else ''
    print('线路1第1集: %s' % first_ep)

    play = sp.playerContent(first_flag, first_ep.split('$')[-1])
    show('播放返回', play)
    print('自测完成')
