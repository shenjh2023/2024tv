# -*- coding: utf-8 -*-
# 影探4K —— FongMi 影视 / 鱼壳 webhtv 单文件 Python 源
# 数据源：影探 CMS（cms.lyyytv.cn） + 放映室解析（fys.lyyytv.cn）
#
# 关于「写着 4K 实际只有 1080P」：
#   CMS 的 vod_remarks 与线路 code（4K(BD) / 4K(YD)）都是后台手填的文本标签，
#   和文件真实分辨率没有关系。实测 4K 线路里确实混着 H.264 High / 1920x1080 的源，
#   抽样 40 部约有 12% 是这种情况。本源只负责把真实地址取出来，不臆测分辨率。

import base64
import json
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait

import requests
from base.spider import Spider

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:          # 纯净 Python 环境（部分壳未带 PyCryptodome）
    AES = None
    unpad = None


# ---------------------------------------------------------------- 纯 Python AES

def _build_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = (p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)) & 0xff
        q ^= (q << 1) & 0xff
        q ^= (q << 2) & 0xff
        q ^= (q << 4) & 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) & 0xff
        x ^= ((q << 2) | (q >> 6)) & 0xff
        x ^= ((q << 3) | (q >> 5)) & 0xff
        x ^= ((q << 4) | (q >> 4)) & 0xff
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r & 0xff


def _expand_key(key):
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def _inv_shift_rows(s):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = s[((c - r) % 4) * 4 + r]
    return out


def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[c * 4:c * 4 + 4]
        out[c * 4 + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        out[c * 4 + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        out[c * 4 + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        out[c * 4 + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return out


def _decrypt_block(block, rk):
    s = [block[i] ^ rk[10][i] for i in range(16)]
    for rnd in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    return bytes([s[i] ^ rk[0][i] for i in range(16)])


def _py_aes_cbc_decrypt(key, data):
    if not data or len(data) % 16:
        data = data[:len(data) - len(data) % 16]
    if not data:
        return b''
    rk = _expand_key(key)
    prev = key
    out = bytearray()
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        plain = _decrypt_block(block, rk)
        out.extend(bytes([plain[i] ^ prev[i] for i in range(16)]))
        prev = block
    pad = out[-1] if out else 0
    if 0 < pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        del out[-pad:]
    return bytes(out)


def _aes_cbc_decrypt(key, data):
    """AES-128-CBC(IV=key) 解密，优先 PyCryptodome，失败降级纯 Python。"""
    if AES is not None:
        try:
            return unpad(AES.new(key, AES.MODE_CBC, key).decrypt(data), 16)
        except Exception:
            pass
    return _py_aes_cbc_decrypt(key, data)


def _b64(value):
    clean = re.sub(r'\s+', '', value or '')
    if not clean:
        return b''
    clean += '=' * (-len(clean) % 4)
    try:
        return base64.b64decode(clean, validate=False)
    except Exception:
        return b''


# ---------------------------------------------------------------- 站点常量

HOST = 'http://cms.lyyytv.cn'
CMS_KEY = 'wP5bvxoc3yv7FoBQENFZuAF0EUYr4LTy'
# 放映室解析：老的 parsesId=3 已下线（Parses.php:63 报 500），现存两条且互不通用
PARSE_API = 'http://fys.lyyytv.cn/api/index?appid=10001&videoUrl='
PARSE_ID_WEB = 5     # 腾讯/爱奇艺/芒果/优酷/B站 页面地址
PARSE_ID_4K = 6      # ym4kjx 下的 mp4/mkv 直链（站点自身 404，必须换链）
DEC_PREFIX = 'https://baidu.con/'
UA = 'okhttp/4.12.0'
TIMEOUT = 20
PARSE_ROUNDS = 2
PLAY_TTL = 300

# 筛选：只保留 nav 的 type_extend 里真实存在的键
FILTER_NAMES = (
    ('class', '类型'),
    ('area', '地区'),
    ('lang', '语言'),
    ('year', '年份'),
    ('star', '演员'),
    ('director', '导演'),
    ('state', '状态'),
    ('version', '版本'),
)

_MEDIA_RE = re.compile(r'\.(?:mp4|m3u8|mkv|flv|ts|mov|wmv|webm|m4v|mpd)$', re.I)
_STREAM_RE = re.compile(r'\.(?:m3u8|mpd)$', re.I)
_4K_HOST_RE = re.compile(r'(?:^|\.)(?:ym4kjx|hd4kjx|sd4kjx|mm4kjx|mv4kjx|vk4kjx)\.lyyytv\.cn$', re.I)


def _text(value):
    return '' if value is None else str(value).strip()


def _page_of(value):
    m = re.match(r'\s*[+-]?(\d+)', '' if value is None else str(value))
    return max(1, int(m.group(1))) if m else 1


def _http_url(value):
    try:
        p = urllib.parse.urlparse(_text(value))
        return p.scheme in ('http', 'https') and bool(p.netloc)
    except Exception:
        return False


def _is_media(url):
    if not _http_url(url):
        return False
    return bool(_MEDIA_RE.search(urllib.parse.urlparse(url).path))


def _is_stream(url):
    if not _http_url(url):
        return False
    return bool(_STREAM_RE.search(urllib.parse.urlparse(url).path))


def _is_4k_source(url):
    if not _http_url(url):
        return False
    host = (urllib.parse.urlparse(url).hostname or '').lower()
    if _4K_HOST_RE.search(host):
        return True
    return _is_media(url) and not _is_stream(url)


# ------------------------------------------------------------ 真分辨率探测
# CMS 只给文本标签，想要真实分辨率只能看文件头：
#   直链全被 CDN 包了一层，首字节 1a45dfa3 = MKV（大量 .mp4 其实是 MKV 容器），
#   否则按 MP4 sample entry 读 width/height。只取前 256KB，够用且不浪费流量。

RES_TTL = 86400
PROBE_BUDGET = 6          # 详情页为探测总共愿意等多久（秒），超时的线路直接不标
_PROBE_BYTES = 49152      # 48KB：MKV 头部一般 5–30KB 就够，实测 40KB 与 256KB 结果一致
_PROBE_SESSION = None


def _probe_session():
    """复用连接：每条线路要打两次 CDN，握手省下来的就是详情页省下来的。"""
    global _PROBE_SESSION
    if _PROBE_SESSION is None:
        s = requests.Session()
        s.trust_env = False
        s.headers.update({'User-Agent': UA, 'Accept-Encoding': 'identity'})
        _PROBE_SESSION = s
    return _PROBE_SESSION


def _mp4_res(buf):
    for tag in (b'hvc1', b'hev1', b'avc1', b'dvh1', b'dvhe', b'av01', b'vp09'):
        start = 0
        while True:
            i = buf.find(tag, start)
            if i < 0:
                break
            start = i + 4
            if i < 4 or i + 32 > len(buf):
                continue
            w = int.from_bytes(buf[i + 28:i + 30], 'big')
            h = int.from_bytes(buf[i + 30:i + 32], 'big')
            if 320 <= w <= 8192 and 120 <= h <= 8192:
                return w, h
    return 0, 0


def _mkv_res(buf):
    for tag in (b'V_MPEGH/ISO/HEVC', b'V_MPEG4/ISO/AVC', b'V_AV1'):
        i = buf.find(tag)
        if i < 0:
            continue
        seg = buf[i:i + 8192]
        vals = {}
        k = 0
        size = len(seg)
        while k < size - 2:
            key = seg[k]
            if key in (0xb0, 0xba) and 0x80 <= seg[k + 1] <= 0x8f:
                n = seg[k + 1] & 0x7f
                if 1 <= n <= 8 and k + 2 + n <= size:
                    if key not in vals:
                        vals[key] = int.from_bytes(seg[k + 2:k + 2 + n], 'big')
                    k += 2 + n
                    continue
            k += 1
        w = vals.get(0xb0, 0)
        h = vals.get(0xba, 0)
        if 320 <= w <= 8192 and 120 <= h <= 8192:
            return w, h
    return 0, 0


def _probe_res(url):
    """返回 (宽, 高)，探不到就 (0, 0)。"""
    try:
        r = _probe_session().get(url, headers={'Range': 'bytes=0-%d' % (_PROBE_BYTES - 1)},
                                 timeout=4, stream=False)
        buf = r.content or b''
    except Exception:
        return 0, 0
    if len(buf) < 2048:
        return 0, 0
    if buf[:4] == b'\x1aE\xdf\xa3':
        return _mkv_res(buf)
    return _mp4_res(buf)


def _probe_line(raw):
    """4K 直链 → parsesId=6 换链 → 读文件头拿真实分辨率。"""
    try:
        target = '%s%s&parsesId=%d' % (PARSE_API, urllib.parse.quote(raw, safe="!'()*"), PARSE_ID_4K)
        body = _probe_session().get(target, timeout=6).text
        real = _resolve_parse(body)
        if not _http_url(real):
            return 0, 0
        return _probe_res(real)
    except Exception:
        return 0, 0


def _res_tag(w, h):
    if not w or not h:
        return ''
    if w >= 3000 or h >= 1800:
        return '2160P'
    if w >= 1800 or h >= 900:
        return '1080P'
    if h >= 620:
        return '720P'
    return '%dP' % h


def _find_url(value):
    if not isinstance(value, dict):
        return ''
    for key in ('url', 'playUrl', 'link'):
        if value.get(key):
            return _text(value[key])
    return _find_url(value.get('data'))


def _resolve_parse(body):
    """解析接口响应 → 真实地址。baidu.con 前缀：前 16 位既是 key 也是 IV。"""
    body = _text(body)
    if not body:
        return ''
    candidate = body
    if body.startswith('{'):
        try:
            found = _find_url(json.loads(body))
            if found:
                candidate = found
        except Exception:
            pass
    if not candidate.startswith(DEC_PREFIX):
        return candidate if candidate.startswith('http') else ''
    rest = candidate[len(DEC_PREFIX):]
    if len(rest) <= 16:
        return ''
    plain = _aes_cbc_decrypt(rest[:16].encode('utf-8'), _b64(rest[16:]))
    result = plain.decode('utf-8', 'replace').strip() if plain else ''
    return result if result.startswith('http') else ''


class Spider(Spider):
    _instance = None
    _inited = False

    def __init__(self):
        Spider._instance = self
        self.extend = ''
        self.session = None
        self._cache = {}

    def init(self, extend=''):
        self.extend = extend or ''
        self.session = self._build_session()
        self._cache = {}
        try:
            super().init(extend)
        except Exception:
            pass
        Spider._inited = True

    # ------------------------------------------------------------ 基础设施

    @staticmethod
    def _build_session():
        s = requests.Session()
        try:
            s.trust_env = False
        except Exception:
            pass
        s.headers.update({'User-Agent': UA, 'Accept-Encoding': 'identity'})
        return s

    def _get(self, url, timeout=TIMEOUT):
        try:
            if self.session is None:
                self.session = self._build_session()
            rsp = self.session.get(url, timeout=timeout)
            if rsp is not None and rsp.status_code == 200:
                return rsp.text or ''
        except Exception:
            pass
        try:
            rsp = requests.get(url, headers={'User-Agent': UA, 'Accept-Encoding': 'identity'},
                               timeout=timeout)
            if rsp.status_code == 200:
                return rsp.text or ''
        except Exception:
            pass
        return ''

    def _cms(self, path, params=None):
        query = urllib.parse.urlencode(params or {})
        body = self._get('%s/api.php/app/%s?%s' % (HOST, path, query))
        if not body:
            raise RuntimeError('影探4K：接口无响应')
        try:
            data = json.loads(body)
        except Exception:
            raise RuntimeError('影探4K：接口返回非 JSON')
        if not isinstance(data, dict):
            raise RuntimeError('影探4K：接口返回结构异常')
        code = data.get('code')
        if code is not None and _text(code) not in ('1', '200'):
            raise RuntimeError('影探4K：接口返回 code=%s' % code)
        return data

    def _cache_get(self, key, ttl):
        item = self._cache.get(key)
        if item and item[0] > time.time():
            return item[1]
        return None

    def _cache_set(self, key, value, ttl):
        self._cache[key] = (time.time() + ttl, value)

    # ------------------------------------------------------------ 数据处理

    @staticmethod
    def _decrypt_lvdou(value):
        original = _text(value)
        if not original.startswith('lvdou+'):
            return original
        key = CMS_KEY[:16].encode('utf-8')
        plain = _aes_cbc_decrypt(key, _b64(original[6:]))
        if not plain:
            return original
        result = plain.decode('utf-8', 'replace').strip()
        return result if result.startswith('http') else original

    @staticmethod
    def _playlist(value):
        parts = []
        for entry in _text(value).split('#'):
            sep = entry.find('$')
            if sep <= 0 or not _text(entry[sep + 1:]):
                continue
            parts.append('%s$%s' % (_text(entry[:sep]), Spider._decrypt_lvdou(entry[sep + 1:])))
        return '#'.join(parts)

    @staticmethod
    def _paginated(data, requested):
        lst = data.get('list') if isinstance(data.get('list'), list) else []
        page = _page_of(data.get('page') if data.get('page') is not None else requested)
        try:
            limit = int(data.get('limit') or 0)
        except (TypeError, ValueError):
            limit = 0
        if limit <= 0:
            limit = 20
        try:
            pagecount = int(data.get('pagecount') or 0)
        except (TypeError, ValueError):
            pagecount = 0
        if pagecount <= 0:
            pagecount = page + (1 if len(lst) >= limit else 0)
        try:
            total = int(data.get('total'))
        except (TypeError, ValueError):
            total = (page - 1) * limit + len(lst) + (1 if pagecount > page else 0)
        data['page'] = page
        data['pagecount'] = pagecount
        data['limit'] = limit
        data['total'] = total
        data['list'] = lst
        return data

    # ------------------------------------------------------------ 壳接口

    def getName(self):
        return '🎬 影探4K'

    def isVideoFormat(self, url):
        return _is_media(url)

    def manualVideoCheck(self):
        return False

    def homeContent(self, filter):
        cached = self._cache_get('home', 6 * 3600)
        if cached:
            return cached
        data = self._cms('nav', {'token': ''})
        classes = []
        filters = {}
        for item in (data.get('list') or []):
            if not isinstance(item, dict):
                continue
            tid = _text(item.get('type_id'))
            name = _text(item.get('type_name'))
            if not tid or not name:
                continue
            classes.append({'type_id': tid, 'type_name': name})
            ext = item.get('type_extend')
            if isinstance(ext, str):
                try:
                    ext = json.loads(ext)
                except Exception:
                    ext = {}
            if not isinstance(ext, dict):
                continue
            groups = []
            for key, label in FILTER_NAMES:
                values = []
                for v in _text(ext.get(key)).split(','):
                    v = _text(v)
                    if v and v not in values:
                        values.append(v)
                if values:
                    groups.append({
                        'key': key,
                        'name': label,
                        'init': '',
                        'value': [{'n': '全部', 'v': ''}] + [{'n': v, 'v': v} for v in values],
                    })
            if groups:
                filters[tid] = groups
        result = {'class': classes, 'filters': filters}
        self._cache_set('home', result, 6 * 3600)
        return result

    def homeVideoContent(self):
        data = self._cms('index_video', {'token': ''})
        vlist = []
        for item in (data.get('list') or []):
            if isinstance(item, dict) and isinstance(item.get('vlist'), list):
                vlist.extend(item['vlist'])
        return {'list': vlist}

    def categoryContent(self, tid, pg, filter, extend):
        page = _page_of(pg)
        tid = _text(tid)
        if not tid:
            return self._paginated({'list': []}, page)
        extend = extend if isinstance(extend, dict) else {}
        params = {'tid': tid, 'pg': str(page), 'limit': '20'}
        for key, _label in FILTER_NAMES:
            value = _text(extend.get(key))
            if value and value.lower() != 'all':
                params[key] = value
        return self._paginated(self._cms('video', params), page)

    def detailContent(self, ids):
        if not isinstance(ids, (list, tuple)):
            ids = [ids]
        result = []
        for vid in ids:
            vid = _text(vid)
            if not vid:
                continue
            data = self._cms('video_detail', {'id': vid}).get('data')
            if not isinstance(data, dict):
                continue
            players = data.get('vod_url_with_player')
            vod = {k: v for k, v in data.items() if k != 'vod_url_with_player'}
            froms = _text(vod.get('vod_play_from')).split('$$$')
            if isinstance(players, list) and players:
                sources = players
            else:
                sources = [{'name': froms[i] if i < len(froms) else '',
                            'url': u, 'code': froms[i] if i < len(froms) else ''}
                           for i, u in enumerate(_text(vod.get('vod_play_url')).split('$$$'))]
            lines = []
            urls = []
            raws = []
            for index, source in enumerate(sources):
                if not isinstance(source, dict):
                    continue
                url = self._playlist(source.get('url'))
                if not url:
                    continue
                code = _text(source.get('code'))
                name = _text(source.get('name')) or code or ('线路%d' % (index + 1))
                # 后台把 4K 写在 code 上、把「联通云/移动云」写在 name 上，
                # 只显示 name 会让人以为没有 4K 线路，所以把 code 并进线路名。
                label = ('%s %s' % (code, name)) if code and code.lower() not in name.lower() else name
                first = url.split('#')[0]
                first = first.split('$')[-1] if '$' in first else first
                lines.append(re.sub(r'[$#]', ' ', label))
                urls.append(url)
                raws.append(first if _is_4k_source(first) else '')

            # 4K 标签是后台手填的，混着 1080P 的源；这里读文件头把真实分辨率标出来，
            # 高的排前面。只探前 3 条 4K，每条 7 秒封顶，失败就当没探到，不拖慢详情页。
            picks = [(i, raws[i]) for i in range(len(raws)) if raws[i]][:3]
            res = {}
            todo = []
            for i, raw in picks:
                hit = self._cache_get('res:' + raw, RES_TTL)
                if hit:
                    res[i] = hit
                else:
                    todo.append((i, raw))
            if todo:
                pool = ThreadPoolExecutor(max_workers=min(3, len(todo)))
                try:
                    jobs = {pool.submit(_probe_line, raw): (i, raw) for i, raw in todo}
                    done, _pending = wait(jobs, timeout=PROBE_BUDGET)
                except Exception:
                    jobs, done = {}, set()
                finally:
                    # 不等慢的那条：超时的线路这次不标，下次打开再试
                    pool.shutdown(wait=False)
                for job in done:
                    i, raw = jobs[job]
                    try:
                        item = job.result()
                    except Exception:
                        continue
                    res[i] = item
                    self._cache_set('res:' + raw, item, RES_TTL)

            order = []
            for i, label in enumerate(lines):
                w, h = res.get(i, (0, 0))
                tag = _res_tag(w, h)
                if tag:
                    label = '%s · %s' % (label, tag)
                order.append((h, i, label))
            order.sort(key=lambda x: (-x[0], x[1]))
            lines = [x[2] for x in order]
            urls = [urls[x[1]] for x in order]

            vod['vod_play_from'] = '$$$'.join(lines)
            vod['vod_play_url'] = '$$$'.join(urls)
            result.append(vod)
        return {'list': result}

    def searchContent(self, key, quick, pg='1'):
        page = _page_of(pg)
        keyword = _text(key)
        if not keyword:
            return self._paginated({'list': []}, page)
        data = self._cms('search', {'text': keyword, 'pg': str(page)})
        data['list'] = [dict(x) for x in (data.get('list') or []) if isinstance(x, dict)]
        for item in data['list']:
            item.pop('type', None)
        return self._paginated(data, page)

    def playerContent(self, flag, id, vipFlags):
        raw = _text(id)
        if raw.count('$') > 0:
            raw = raw.split('$')[-1]
        raw = self._decrypt_lvdou(raw)
        if not raw:
            return {'parse': 0, 'url': '', 'header': {'User-Agent': UA}}

        cached = self._cache_get('play:' + raw, PLAY_TTL)
        if cached:
            return {'parse': 0, 'url': cached, 'header': {'User-Agent': UA}}

        if _is_4k_source(raw):
            # 4K 线路在源站是 404 的裸直链，必须经 parsesId=6 换成移动云盘/华为云地址
            tag = '4K'
            url = self._parse(raw, PARSE_ID_4K)
            if not url:
                tag = '4K-FAIL'
                url = raw
        elif _is_stream(raw):
            tag = 'STREAM'
            url = raw
        else:
            tag = 'WEB'
            url = self._parse(raw, PARSE_ID_WEB) or (raw if _is_media(raw) else '')

        if url:
            self._cache_set('play:' + raw, url, PLAY_TTL)
        print('[影探4K] %s -> %s' % (tag, url[:110]))
        return {'parse': 0, 'url': url, 'header': {'User-Agent': UA}}

    def _parse(self, raw, parse_id):
        target = '%s%s&parsesId=%d' % (PARSE_API, urllib.parse.quote(raw, safe="!'()*"), parse_id)
        for rnd in range(PARSE_ROUNDS):
            if rnd:
                time.sleep(0.4 * rnd)
            body = self._get(target, 25)
            resolved = _resolve_parse(body)
            if resolved:
                return resolved
        return ''

    def localProxy(self, param):
        return None

    def destroy(self):
        try:
            if self.session is not None:
                self.session.close()
        except Exception:
            pass
        self.session = None
        self._cache = {}
