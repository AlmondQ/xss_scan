# encoding: utf-8
import urllib2
import re
from bs4 import BeautifulSoup
import hashlib
import urlparse

to_test = []
urlsim_hash = []


def get_param_url(url):
    global urlsim_hash
    reParamUrl = re.compile(r"http://.*\?.*=.*")
    response = urllib2.urlopen(url)
    soup = BeautifulSoup(response, "html.parser", from_encoding="utf-8")
    links = soup.find_all("a", href=reParamUrl)
    for link in links:
        url_hash = url_similarity(link['href'])
        if url_hash in urlsim_hash:
            continue
        else:
            #print link["href"]
            urlsim_hash.append(url_hash)
            to_test.append(link['href'])


'''
url相似度判断
主要取4个值
1. netloc的hash值
2. path字符串拆解成列表的列表长度(尾页特征specially定义)
3. path中字符串的长度
4. query参数名hash a=1&b=2&c=3 : hash('abc')
'''


def url_similarity(url):
    netloc_value = 0
    path_value = 0
    query_value = 0
    hash_size = 10000000
    tmp = urlparse.urlparse(url)
    netloc = tmp[1]
    path = tmp[2][1:]
    query = tmp[4]
    url_value = 0
    try:
        if len(netloc)>0:
            netloc = netloc.lower()
            netloc_value = hash(hashlib.new("md5", netloc).hexdigest()) % hash_size

        if len(path)>0:
            path = path.lower()
            path_list = path.split("/")[:-1]
            # path="a/b/c/d.html"
            if len(path.split("/")[-1].split(".")) > 1:
                tail = path.split("/")[-1].split(".")[-1]
            # path = ''
            elif len(path.split("/")) == 1:
                tail = path
            # path="a/"
            else:
                tail = "1"
            path_list.append(tail)
            path_length = len(path_list)
            for i in range(path_length):
                i_length = len(path_list[i]) * (10**(i+1))
                path_value += i_length
            path_value = hash(hashlib.new("md5", str(path_value)).hexdigest()) % hash_size

        if len(query)>0:
            query = query.lower()
            key_str = ""
            tmpp = query.split("&")
            for p in tmpp:
                key_str += p.split("=")[0]
            query_value = hash(hashlib.new("md5", key_str).hexdigest()) % hash_size

        url_value = hash(hashlib.new("md5", str(netloc_value + path_value + query_value)).hexdigest()) % hash_size
    except Exception, e:
        print str(e)
    finally:
        return url_value


def loop_get(url, n):
    get_param_url(url)
    i = 0
    for link in to_test:
        if i == n:
            break
        get_param_url(link)
        i += 1
    return to_test


# if __name__ == '__main__':
#     print url_similarity("http://news.baidu.com/ns?cl=2&rn=20&tn=newsA1D4C5&word=")
#     print url_similarity("http://news.baidu.com/ns?cl=2A1D4C5&rn=20&tn=newsA1D4C5&word=")