# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re, operator, datetime, hashlib,json
from lib.core.common import *


# 作者：咚咚呛
# 功能：根据已知的异常风险，进行信息聚合，根据时间线排序，获取黑客的行动轨迹

class Data_Aggregation:
    def __init__(self):
        # 可能存在的黑客入口点信息
        self.begins = []
        # 检测结果信息
        self.result_infos = []
        # 本次新增异常风险,与历史进行数据对比
        self.dif_result_infos = []
        # 是否差异扫描
        self.diffect = False

    # 读取db文件，提取hash内容，进行结果判断存在哪些新增风险。
    def result_db_filter(self):
        old_db = []
        DB_PATH = get_value('DB_PATH')
        with open(DB_PATH) as f:
            for line in f:
                old_db.append(line.strip())
        for info in self.result_infos:
            hash_txt = info['checkname'] + info['vulname'] + info['file'] + info['pid'] + info['mtime'] + info['minfo']
            md5obj = hashlib.md5()
            md5obj.update(hash_txt.encode("utf8"))
            hashinfo = md5obj.hexdigest()
            if not hashinfo in old_db:
                self.dif_result_infos.append(info)
        # 写检测结果到db文件
        self.write_result_to_db()

    # 写检测结果到db文件
    def write_result_to_db(self):
        DB_PATH = get_value('DB_PATH')
        # 写结果文件到db
        with open(DB_PATH, 'w') as f:
            for info in self.result_infos:
                hash_txt = info['checkname'] + info['vulname'] + info['file'] + info['pid'] + info['mtime'] + info['minfo']
                md5obj = hashlib.md5()
                md5obj.update(hash_txt.encode("utf8"))
                hashinfo = md5obj.hexdigest()
                f.write(hashinfo + '\n')

    # 黑客攻击可能存在的入口点
    def attack_begins(self):
        try:
            attack_begins = os.popen(
                "netstat -ntpl 2>/dev/null | grep -v '127.0.0.1' |awk '{if (NR>1){print $4\" \"$7}}'").read().splitlines()
            for infors in attack_begins:
                if not '/' in infors: continue
                if not ':' in infors: continue
                ip_port = infors.split(' ')[0]  # 开放端口
                pid_name = infors.split(' ')[1]  # 钓鱼进程
                self.begins.append({'ip_port': ip_port, 'pid_name': pid_name})
        except:
            return

    # 追溯溯源信息
    def agregation(self):
        suggestion = get_value('suggestion')
        programme = get_value('programme')

        if len(self.result_infos) > 0:
            say_info, i = u'-' * 30 + u'\n', 1
            #say_info += u'根据系统分析的情况，溯源后的攻击行动轨迹为：\n' if not self.diffect else u'根据系统差异分析的情况，溯源后的攻击行动轨迹为：\n'
            say_info += 'After analysis, the attack will be ：\n' if not self.diffect else 'After analysis, the attack will be：\n'
            # 入口点信息
            for begin_info in self.begins:
                say_info += u'[Beginning Info] process service %s port %s is open worldwide, coubd be the attack point.\n' % (
                    begin_info['pid_name'], begin_info['ip_port'])

            programme_info = u'\ninitial proposal：\n'
            # 根据时间排序
            self.result_infos.sort(key=operator.itemgetter('mtime'))
            for result_info in self.result_infos:
                if result_info['checkname'] == u'常规后门检测':
                    say_info += u"[%d][%s] hacker in %s，do %s implant,%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['vulname'], result_info['minfo'])
                    if suggestion: say_info = say_info + "           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'配置类安全检测':
                    say_info += u"[%d][%s] hacker in %s，do %s change，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['vulname'], result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'文件类安全检测':
                    say_info += u"[%d][%s] hacker in %s，implant file %s，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['file'], result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'主机历史操作类安全检测':
                    say_info += u"[%d][%s] hacker in %s，do malicious operation，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'日志类安全检测':
                    say_info += u"[%d][%s] hacker in %s，user %s login，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info[u'所属用户'], result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'网络链接类安全检测':
                    say_info += u"[%d][%s] hacker in %s，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'进程类安全检测':
                    say_info += u"[%d][%s] hacker in %s，run process %s，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['pid'], result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'Rootkit类安全检测':
                    say_info += u"[%d][%s] hack in %s，implant Rootkit backdoor，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == u'系统初始化检测':
                    say_info += u"[%d][%s] hacker in %s，setting system alias ，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == 'User_Analysis':
                    say_info += u"[%d][%s] hacker in %s，do account modify ，%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['minfo'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                if result_info['checkname'] == 'Webshell_Analysis':
                    say_info += u"[%d][%s] hacker in %s，implant webshell%s\n" % (
                        i, result_info['level'], result_info['mtime'] if result_info['mtime'] else 'unknown',
                        result_info['file'])
                    if suggestion: say_info = say_info + u"           suggestion：%s\n" % result_info['consult']
                    if programme and result_info['programme']: programme_info += u"[%d] %s\n" % (i, result_info['programme'])
                i += 1
            if programme:
                say_info += programme_info

            file_write(say_info)
            print(
                say_info.replace(u'[risk]', u'[\033[1;31mrisk\033[0m]').replace(u'[suspicious]', u'[\033[1;33msuspicious\033[0m]').replace(
                    u'[Beginning Info]]', u'[\033[1;32mBeginning Info]\033[0m]'))
        else:
            say_info = u'-' * 30 + u'\n'
            say_info += u'no intrusion this time \n' if not self.diffect else u'no intrusion this time \n'
            print(say_info)
            file_write(say_info)

    def run(self):
        self.diffect = get_value('diffect')
        self.result_infos = get_value('RESULT_INFO')
        self.result_infos = reRepeat(self.result_infos)
        self.result_db_filter()
        self.attack_begins()
        if self.diffect: self.result_infos = self.dif_result_infos
        self.agregation()

        # 初始化日志接口
        logger = loging()
        for info in self.result_infos:
            logger.info(json.dumps(info, ensure_ascii=False))
