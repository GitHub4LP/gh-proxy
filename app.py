# -*- coding: utf-8 -*-
import re
import os
import requests
import time
import threading

from flask import Flask, Response, redirect, request, jsonify
from requests.exceptions import (
    ChunkedEncodingError,
    ContentDecodingError, ConnectionError, StreamConsumedError)
from requests.utils import (
    stream_decode_response_unicode, iter_slices, CaseInsensitiveDict)
from urllib3.exceptions import (
    DecodeError, ReadTimeoutError, ProtocolError)
from urllib.parse import quote

def keep_alive(service_url, interval=60):
    """
    定期访问指定地址以保活服务。

    :param service_url: 服务的 URL 地址
    :param interval: 访问间隔时间（秒）
    """
    while True:
        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                print(f"服务保活成功: {service_url}")
            else:
                print(f"服务保活失败: 状态码 {response.status_code}")
        except Exception as e:
            print(f"无法访问服务 {service_url}: {e}")
        time.sleep(interval)

# config
# 分支文件使用jsDelivr镜像的开关，0为关闭，默认关闭
jsdelivr = 0
size_limit = 1024 * 1024 * 1024 * 999  # 允许的文件大小，默认999GB，相当于无限制了 https://github.com/hunshcn/gh-proxy/issues/8

"""
  先生效白名单再匹配黑名单，pass_list匹配到的会直接302到jsdelivr而忽略设置
  生效顺序 白->黑->pass，可以前往https://github.com/hunshcn/gh-proxy/issues/41 查看示例
  每个规则一行，可以封禁某个用户的所有仓库，也可以封禁某个用户的特定仓库，下方用黑名单示例，白名单同理
  user1 # 封禁user1的所有仓库
  user1/repo1 # 封禁user1的repo1
  */repo1 # 封禁所有叫做repo1的仓库
"""
white_list = '''
'''
black_list = '''
'''
pass_list = '''
'''

HOST = '0.0.0.0'  # 监听地址，建议监听本地然后由web服务器反代
PORT = 7860  # 监听端口
ASSET_URL = 'https://hunshcn.github.io/gh-proxy'  # 主页

white_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in white_list.split('\n') if i]
black_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in black_list.split('\n') if i]
pass_list = [tuple([x.replace(' ', '') for x in i.split('/')]) for i in pass_list.split('\n') if i]
app = Flask(__name__)
CHUNK_SIZE = 1024 * 10
index_html = requests.get(ASSET_URL, timeout=10).text
icon_r = requests.get(ASSET_URL + '/favicon.ico', timeout=10).content
exp1 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$')
exp2 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$')
exp3 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$')
exp4 = re.compile(r'^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$')
exp5 = re.compile(r'^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$')

requests.sessions.default_headers = lambda: CaseInsensitiveDict()

@app.route('/config')
def get_config():
    # 定义要返回的 JSON 数据
    config = {
        "version": "5.10.0",
    }
    return jsonify(config)

@app.route('/')
def index():
    if 'q' in request.args:
        return redirect('/' + request.args.get('q'))
    return index_html


@app.route('/favicon.ico')
def icon():
    return Response(icon_r, content_type='image/vnd.microsoft.icon')


def iter_content(self, chunk_size=1, decode_unicode=False):
    """rewrite requests function, set decode_content with False"""

    def generate():
        # Special case for urllib3.
        if hasattr(self.raw, 'stream'):
            try:
                for chunk in self.raw.stream(chunk_size, decode_content=False):
                    yield chunk
            except ProtocolError as e:
                raise ChunkedEncodingError(e)
            except DecodeError as e:
                raise ContentDecodingError(e)
            except ReadTimeoutError as e:
                raise ConnectionError(e)
        else:
            # Standard file-like object.
            while True:
                chunk = self.raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        self._content_consumed = True

    if self._content_consumed and isinstance(self._content, bool):
        raise StreamConsumedError()
    elif chunk_size is not None and not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an int, it is instead a %s." % type(chunk_size))
    # simulate reading small chunks of the content
    reused_chunks = iter_slices(self._content, chunk_size)

    stream_chunks = generate()

    chunks = reused_chunks if self._content_consumed else stream_chunks

    if decode_unicode:
        chunks = stream_decode_response_unicode(chunks, self)

    return chunks


def check_url(u):
    for exp in (exp1, exp2, exp3, exp4, exp5):
        m = exp.match(u)
        if m:
            return m
    return False


@app.route('/<path:u>', methods=['GET', 'POST'])
def handler(u):
    u = u if u.startswith('http') else 'https://' + u
    if u.rfind('://', 3, 9) == -1:
        u = u.replace('s:/', 's://', 1)  # uwsgi会将//传递为/
    pass_by = False
    m = check_url(u)
    if m:
        m = tuple(m.groups())
        if white_list:
            for i in white_list:
                if m[:len(i)] == i or i[0] == '*' and len(m) == 2 and m[1] == i[1]:
                    break
            else:
                return Response('Forbidden by white list.', status=403)
        for i in black_list:
            if m[:len(i)] == i or i[0] == '*' and len(m) == 2 and m[1] == i[1]:
                return Response('Forbidden by black list.', status=403)
        for i in pass_list:
            if m[:len(i)] == i or i[0] == '*' and len(m) == 2 and m[1] == i[1]:
                pass_by = True
                break
    else:
        return Response('Invalid input.', status=403)

    if (jsdelivr or pass_by) and exp2.match(u):
        u = u.replace('/blob/', '@', 1).replace('github.com', 'cdn.jsdelivr.net/gh', 1)
        return redirect(u)
    elif (jsdelivr or pass_by) and exp4.match(u):
        u = re.sub(r'(\.com/.*?/.+?)/(.+?/)', r'\1@\2', u, 1)
        _u = u.replace('raw.githubusercontent.com', 'cdn.jsdelivr.net/gh', 1)
        u = u.replace('raw.github.com', 'cdn.jsdelivr.net/gh', 1) if _u == u else _u
        return redirect(u)
    else:
        if exp2.match(u):
            u = u.replace('/blob/', '/raw/', 1)
        if pass_by:
            url = u + request.url.replace(request.base_url, '', 1)
            if url.startswith('https:/') and not url.startswith('https://'):
                url = 'https://' + url[7:]
            return redirect(url)
        u = quote(u, safe='/:')
        return proxy(u)


def proxy(u, allow_redirects=False):
    headers = {}
    r_headers = dict(request.headers)
    if 'Host' in r_headers:
        r_headers.pop('Host')
    try:
        url = u + request.url.replace(request.base_url, '', 1)
        if url.startswith('https:/') and not url.startswith('https://'):
            url = 'https://' + url[7:]
        r = requests.request(method=request.method, url=url, data=request.data, headers=r_headers, stream=True, allow_redirects=allow_redirects)
        headers = dict(r.headers)

        if 'Content-length' in r.headers and int(r.headers['Content-length']) > size_limit:
            return redirect(u + request.url.replace(request.base_url, '', 1))

        def generate():
            for chunk in iter_content(r, chunk_size=CHUNK_SIZE):
                yield chunk

        if 'Location' in r.headers:
            _location = r.headers.get('Location')
            if check_url(_location):
                headers['Location'] = '/' + _location
            else:
                return proxy(_location, True)

        return Response(generate(), headers=headers, status=r.status_code)
    except Exception as e:
        headers['content-type'] = 'text/html; charset=UTF-8'
        return Response('server error ' + str(e), status=500, headers=headers)

if __name__ == '__main__':
    # 获取服务地址
    SERVICE_URL = os.environ.get("SELF_URL")
    if SERVICE_URL:
        # 启动保活任务线程，传入服务地址
        threading.Thread(target=keep_alive, args=(SERVICE_URL,), daemon=True).start()
        print(f"启动保活任务，定期访问: {SERVICE_URL}")
    else:
        print("环境变量 SERVICE_URL 未设置，不启动保活任务。")
    app.run(host=HOST, port=PORT, debug=False)
