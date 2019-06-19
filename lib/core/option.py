# coding:utf-8

import os, optparse, time
from lib.core.option import *
from lib.core.globalvar import *
from lib.core.common import *
from lib.plugins.Host_Info import *
from lib.plugins.File_Analysis import *
from lib.plugins.History_Analysis import *
from lib.plugins.Proc_Analysis import *
from lib.plugins.Network_Analysis import *
from lib.plugins.Backdoor_Analysis import *
from lib.plugins.User_Analysis import *
from lib.plugins.Config_Analysis import *
from lib.plugins.Log_Analysis import *
from lib.plugins.Rootkit_Analysis import *
from lib.plugins.Webshell_Analysis import *
from lib.plugins.Sys_Init import *
from lib.plugins.Search_File import *
from lib.core.data_aggregation import *


def main(path):
    parser = optparse.OptionParser()
    parser.add_option("--version", dest="version", default=False, action='store_true', help="show version")

    group = optparse.OptionGroup(parser, "Mode", "GScan running mode options")
    group.add_option("--overseas", dest="overseas", default=False, action='store_true', help="you are in overseas, will not match oversea IP")
    group.add_option("--full", dest="full_scan", default=False, action='store_true', help="full scan")
    group.add_option("--debug", dest="debug", default=False, action='store_true', help="debug mode")
    group.add_option("--dif", dest="diffect", default=False, action='store_true', help="compare last scan result")
    group.add_option("--sug", dest="suggestion", default=False, action='store_true', help="suggestion")
    group.add_option("--pro", dest="programme", default=False, action='store_true', help="proposal ")

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Optimization", "Optimization options")
    group.add_option("--time", dest="time", type='string',
                     help="show modified files in given period，example: --time='2019-05-07 00:00:00~2019-05-07 23:00:00'")
    group.add_option("--job", dest="job", default=False, action='store_true', help="cron job setting, default run at 0:00 per day ")
    group.add_option("--hour", dest="hour", type='string', help="run by N hours")
    group.add_option("--log", dest="logdir", default=False, action='store_true', help="package all system security log (not implement yet")
    parser.add_option_group(group)

    options, _ = parser.parse_args()

    # 初始化全局模块
    init()
    # 设置调试模式
    set_value('DEBUG', True if options.debug else False)
    # 设置国内ip模式
    set_value('Overseas', True if options.overseas else False)
    # 设置手工排查建议
    set_value('suggestion', True if options.suggestion else False)
    # 设置风险处理方案
    set_value('programme', True if options.programme else False)
    # 设置扫描模式为差异扫描
    set_value('diffect', True if options.diffect else False)
    # 设置扫描模式为完全扫描
    set_value('SCAN_TYPE', 2 if options.full_scan else 1)

    # 系统执行目录
    set_value('SYS_PATH', path)
    # 扫描日志目录
    set_value('LOG_PATH', path + "/log/gscan.log")
    # 结果记录目录
    set_value('DB_PATH', path + "/db/db.txt")
    # 扫描结果
    set_value('RESULT_INFO', [])

    if options.logdir:
        print('\033[1;32m begin backup system log ...\033[0m\n')
        print('\033[1;32m this function is not support yet \033[0m\n')
    elif options.job:
        print('\033[1;32m add cron table job, should do scan first before this\033[0m\n')
        if cron_write('0' if not options.hour else options.hour):
            print('done the add cron table, please checking by "crontab -l" command ')
        else:
            print('\033[1;31m failed to add into cron table, please add manually by reference "crontab -e"\033[0m\n')
    elif options.time:
        print('\033[1;32m Begin file search ...\033[0m\n')
        Search_File(options.time).run()
    elif options.version:
        return
    else:
        # 创建日志文件
        mkfile()
        file_write('begin scan current system security status ...\n')
        print('\033[1;32mbegin scan current system security status...\033[0m')
        # 获取恶意特征信息
        get_malware_info(path)
        # 主机信息获取
        Host_Info().run()
        # 系统初始化检查
        SYS_INIT().run()
        # 文件类安全检测
        File_Analysis().run()
        # 主机历史操作类扫描
        History_Analysis().run()
        # 主机进程类安全扫描
        Proc_Analysis().run()
        # 网络链接类安全扫描
        Network_Analysis().run()
        # 后门类扫描
        Backdoor_Analysis().run()
        # 账户类扫描
        User_Analysis().run()
        # 安全日志类
        Log_Analysis().run()
        # 安全配置类
        Config_Analysis().run()
        # rootkit检测
        Rootkit_Analysis().run()
        # WEBShell类扫描
        Webshell_Analysis().run()
        # 漏洞扫描

        # 路径追溯
        Data_Aggregation().run()

        # 输出报告
        print('-' * 30)
        print('\033[1;32m scan finished, scan result can be found in  %s \033[0m' % get_value('LOG_PATH'))
