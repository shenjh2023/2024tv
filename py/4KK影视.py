# coding=utf-8
# !/usr/bin/python
# Pomo 4K原盘 TVBox爬虫
# 支持磁力链接播放（需TVBox配置磁力解析器）
import re
import sys
from urllib.parse import quote

sys.path.append('..')
from base.spider import Spider


class Spider(Spider):

    def init(self, extend=""):
        pass

    def getName(self):
        return "Pomo4K"

    def isVideoFormat(self, url):
        return False

    def manualVideoCheck(self):
        pass

    def destroy(self):
        pass

    host = 'https://pomo.mom'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
        'Referer': 'https://pomo.mom/',
    }

    # 分类配置
    CATEGORIES = {
        'home': {'name': '首页', 'url': ''},
        'huayu': {'name': '华语热门', 'url': 'huayurm'},
        'jiating': {'name': '家庭影院', 'url': 'jiating'},
        'donghua': {'name': '动画大电影', 'url': 'donghuadadiany'},
        'lengmen': {'name': '冷门佳片', 'url': 'lengmenjiapian'},
        'top250': {'name': 'TOP250', 'url': 'paihangbang'},
        'languang': {'name': '蓝光原盘', 'url': 'sort/12'},
        'dianshiju': {'name': '剧集', 'url': 'dianshiju'},
    }

    def homeContent(self, filter):
        result = {}
        classes = []
        for tid, info in self.CATEGORIES.items():
            classes.append({
                'type_name': info['name'],
                'type_id': tid
            })
        result['class'] = classes
        result['filters'] = {}
        return result

    def homeVideoContent(self):
        return self._parse_list(f'{self.host}/')

    def categoryContent(self, tid, pg, filter, extend):
        cat = self.CATEGORIES.get(tid)
        if not cat:
            return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 16, 'total': 0}

        if cat['url']:
            url = f'{self.host}/{cat["url"]}'
        else:
            url = f'{self.host}/'

        if int(pg) > 1:
            # 首页用 /page/N，其他分类用 /分类/page/N
            if cat['url']:
                url = f'{self.host}/{cat["url"]}/page/{pg}'
            else:
                url = f'{self.host}/page/{pg}'

        result = self._parse_list(url)
        result['page'] = pg
        result['pagecount'] = 9999
        result['limit'] = 16
        result['total'] = 999999
        return result

    def _parse_list(self, url):
        """解析列表页，返回视频列表"""
        try:
            resp = self.fetch(url, headers=self.headers)
            text = self._get_text(resp)
            videos = []
            seen = set()

            # 找到内容区域（All 4K Movies 或 <main> 之后）
            start = text.find('All 4K Movies')
            if start == -1:
                start = text.find('<main')
            if start == -1:
                start = 0
            section = text[start:]

            # 匹配所有 uploadfile 图片
            img_pattern = r'<img[^>]*src="([^"]*uploadfile[^"]*)"[^>]*alt="([^"]*)"[^>]*>'
            pos = 0
            while True:
                img_match = re.search(img_pattern, section[pos:])
                if not img_match:
                    break

                img_src = img_match.group(1)
                img_alt = img_match.group(2)
                img_start = pos + img_match.start()
                img_end = pos + img_match.end()

                # 向前找最近的 <a href="https://pomo.mom/数字">
                before = section[max(0, img_start - 2000):img_start]
                a_match = None
                for m in re.finditer(r'<a\s+href="https://pomo\.mom/(\d+)(?:\.html)?"', before):
                    a_match = m

                if a_match:
                    vid = a_match.group(1)
                    if vid not in seen:
                        seen.add(vid)
                        videos.append({
                            'vod_id': vid,
                            'vod_name': img_alt,
                            'vod_pic': img_src,
                            'vod_remarks': ''
                        })

                pos = img_end

            return {'list': videos}
        except Exception as e:
            print(f'[Pomo] 解析列表出错: {e}')
            return {'list': []}

    def detailContent(self, ids):
        try:
            vid = ids[0]
            url = f'{self.host}/{vid}.html'
            resp = self.fetch(url, headers=self.headers)
            text = self._get_text(resp)

            # 标题
            title_match = re.search(r'<h2 class="x-dbjs-title">([^<]+)</h2>', text)
            title = title_match.group(1).strip() if title_match else ''

            # 海报
            poster_match = re.search(r'<div class="x-dbjs-poster"><img src="([^"]+)"', text)
            poster = poster_match.group(1) if poster_match else ''

            # 元信息
            meta = {}
            meta_rows = re.findall(r'<div class="meta-row[^"]*"><span>([^<]+)</span>([^<]+)</div>', text)
            for label, value in meta_rows:
                label = label.strip().replace('：', '')
                meta[label] = value.strip()

            # 演员（特殊处理 actors 行）
            actors_match = re.search(r'<div class="meta-row actors[^"]*"><span>演员阵容：</span>([^<]+)</div>', text)
            actors = actors_match.group(1).strip() if actors_match else meta.get('演员阵容', '')

            # 导演
            director = meta.get('导演', '')

            # 类型
            type_name = meta.get('类型', '')

            # 年份（从时间提取）
            year = ''
            time_str = meta.get('时间', '')
            if time_str:
                year_match = re.search(r'(\d{4})', time_str)
                if year_match:
                    year = year_match.group(1)

            # 简介
            desc_match = re.search(r'<div class="x-dbjs-desc-block[^"]*"><h3[^>]*>剧情简介</h3><p>([^<]+)</p>', text)
            desc = desc_match.group(1).strip() if desc_match else ''

            # 磁力链接（去重）
            magnets = re.findall(r'data-url="(magnet:\?xt=urn:btih:[^"]+)"', text)
            unique_magnets = []
            seen_mag = set()
            for m in magnets:
                if m not in seen_mag:
                    seen_mag.add(m)
                    unique_magnets.append(m)

            # 提取每个磁力链接对应的文件名和大小
            playlists = []
            # 从 download-item 中提取
            items = re.findall(r'<div class="download-item">(.*?)</div>\s*</div>', text, re.DOTALL)
            seen_items = set()
            for item in items:
                mag_match = re.search(r'data-url="(magnet:\?xt=urn:btih:[^"]+)"', item)
                if not mag_match:
                    continue
                mag = mag_match.group(1)
                if mag in seen_items:
                    continue
                seen_items.add(mag)

                # 提取文件名
                name_match = re.search(r'class="x-dbjs-download-link[^"]*"[^>]*>([^<]+)</a>', item)
                file_name = name_match.group(1).strip() if name_match else ''

                # 提取大小
                size_match = re.search(r'<span class="file-size">\[([^\]]+)\]</span>', item)
                size = size_match.group(1).strip() if size_match else ''

                # 构建标题
                if file_name and size:
                    play_title = f"{file_name} [{size}]"
                elif file_name:
                    play_title = file_name
                elif size:
                    play_title = f"磁力 [{size}]"
                else:
                    play_title = f"磁力{len(playlists)+1}"

                playlists.append({
                    'title': play_title[:80],  # 限制长度
                    'url': mag
                })

            # 兜底：如果 download-item 解析失败，直接用磁力链接
            if not playlists and unique_magnets:
                for i, mag in enumerate(unique_magnets):
                    playlists.append({
                        'title': f'磁力{i+1}',
                        'url': mag
                    })

            # 网盘链接（夸克网盘）
            pan_links = re.findall(r'data-url="(https://pan\.quark\.cn/s/[^"]+)"', text)
            pan_list = []
            seen_pan = set()
            for pan in pan_links:
                if pan not in seen_pan:
                    seen_pan.add(pan)
                    pan_list.append(pan)

            # 构建播放列表
            mag_play_url = ''
            pan_play_url = ''

            if playlists:
                mag_play_url = '#'.join([f"{p['title']}${p['url']}" for p in playlists])

            if pan_list:
                pan_play_url = '#'.join([f"夸克网盘{i+1}${url}" for i, url in enumerate(pan_list)])

            # 组装多播放源
            play_from = []
            play_url = []
            if mag_play_url:
                play_from.append('磁力')
                play_url.append(mag_play_url)
            if pan_play_url:
                play_from.append('夸克网盘')
                play_url.append(pan_play_url)

            if not play_from:
                play_from = ['磁力']
                play_url = [f'正片${vid}']

            vod = {
                'vod_id': vid,
                'vod_name': title,
                'type_name': type_name,
                'vod_year': year,
                'vod_remarks': f"IMDB {meta.get('IMDB', '')}" if meta.get('IMDB') else '',
                'vod_actor': actors,
                'vod_director': director,
                'vod_content': desc,
                'vod_pic': poster,
                'vod_play_from': '$$$'.join(play_from),
                'vod_play_url': '$$$'.join(play_url),
            }

            return {'list': [vod]}
        except Exception as e:
            print(f'[Pomo] 解析详情出错: {e}')
            return {'list': []}

    def searchContent(self, key, quick, pg="1"):
        try:
            url = f'{self.host}/?keyword={quote(key)}'
            if int(pg) > 1:
                url = f'{self.host}/page/{pg}?keyword={quote(key)}'
            result = self._parse_list(url)
            result['page'] = pg
            result['pagecount'] = 9999
            result['limit'] = 16
            result['total'] = 999999
            return result
        except Exception as e:
            print(f'[Pomo] 搜索出错: {e}')
            return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 16, 'total': 0}

    def playerContent(self, flag, id, vipFlags):
        """
        OK影视磁力播放配置：
        - 磁力链接: parse=0, jx=1 触发内置解析
        - 夸克网盘: parse=1 走外部解析
        """
        if id.startswith('magnet:'):
            return {
                'parse': 0,
                'jx': 1,
                'url': id,
                'header': '',
            }
        elif id.startswith('https://pan.quark.cn'):
            return {
                'parse': 1,
                'url': id,
                'header': '',
            }
        else:
            return {
                'parse': 0,
                'jx': 1,
                'url': id,
                'header': '',
            }

    def localProxy(self, param):
        pass

    def _get_text(self, resp):
        """兼容不同返回类型获取文本"""
        if hasattr(resp, 'text'):
            return resp.text
        elif hasattr(resp, '_data'):
            return resp._data.decode('utf-8') if hasattr(resp._data, 'decode') else str(resp._data)
        else:
            return resp.decode('utf-8') if hasattr(resp, 'decode') else str(resp)
