import os
from xml.etree.ElementTree import *
import xml.parsers.expat
import zipfile
from base64 import b64decode
# import commands python2 module
import subprocess  # commands > subprocess
import codecs
import getopt
import subprocess
import binascii
import string
import sys
import csv
import datetime
import struct
import codecs
import re
import logging
import glob
import shutil
import platform
import time
import hashlib


###################
# defined function
###################


def execute_utils(program):
    try:
        os.system(program)
    except Exception as error:
        print('  [*] execute utils function error')


def memdump(osarch):
    print("[+] Memory Dumping")

    if osarch == '1':
        #print("winpmem32 ---------------")
        # execute_utils('utils\\dumpit3.exe')
        execute_utils('utils\\winpmem86.exe artifacts\\windows10.aff4')
    else:
        #print("winpmem64 ---------------")
        # execute_utils('utils\\dumpit.exe')
        execute_utils('utils\\winpmem64.exe artifacts\\windows10.aff4')

    output_file = 'shimcache.txt'  # arg
    do_local = True

    if osarch == '1':
        #print("ev_x86 ---------------")
        os.spawnl(os.P_NOWAIT, 'utils\\ev_x86.exe',
                  'utils\\ev_x86.exe')  # spawnl 백그라운드로 동시 실행 가능
    else:
        #print("ev_x64 ---------------")
        os.spawnl(os.P_NOWAIT, 'utils\\ev_x64.exe', 'utils\\ev_x64.exe')


def ahnreportexe(osarch):
    print("[+] plz save ahnrpt report")
    if osarch == '1':
        # print("ahnrpt----------")
        execute_utils('utils\\AhnRpt_x86.exe')
    else:
        # print("ahnrpt64---------")
        execute_utils('utils\\AhnRpt_x64.exe')


def collect_hash(check_platform, check_sig_vt):
    if check_platform == '2':
        execute_utils(
            'echo [*] ALLUSERSPROFILE Hashes_Dates64 > artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'utils\\md5deep64.exe -u -t -r "%appdata%\\Microsoft\\Windows\\Start Menu\\*" >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'echo [*] Start Menu Hashes_Dates64 >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'utils\\md5deep64.exe -u -t -r "%ProgramData%\\Microsoft\\Windows\\Start Menu\\*" >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'echo [*] WINDIR Hashes_Dates64 >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'utils\\md5deep64.exe -u -t -r "%WINDIR%\\system32\\*" >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'echo [*] SystemDrive Hashes_Dates64 >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'utils\\md5deep64.exe -u -t -r "%systemdrive%\\Windows\\Temp\\*" >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'echo [*] TEMP Hashes_Dates64 >> artifacts\\hash\\Hashes_Dates64.txt')
        execute_utils(
            'utils\\md5deep64.exe -u -t -r "%TEMP%\\*" >> artifacts\\hash\\Hashes_Dates64.txt')  # docker랑 충돌 docker를 종료해야함
    else:
        execute_utils(
            'echo [*] ALLUSERSPROFILE Hashes_Dates32 > artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'utils\\md5deep32.exe -u -t -r "%ALLUSERSPROFILE%\\Start Menu\\*" >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'echo [*] ProgramData Hashes_Dates32 >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'utils\\md5deep32.exe -u -t -r "%ProgramData%\\Microsoft\\Windows\\Start Menu\\*" >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'echo [*] WINDIR Hashes_Dates32 >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'utils\\md5deep32.exe -u -t -r "%WINDIR%\\system32\\*" >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'echo [*] SystemDrive Hashes_Dates32 >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'utils\\md5deep32.exe -u -t -r "%SystemDrive%\\Temp\\*" >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'echo [*] TEMP Hashes_Dates32 >> artifacts\\hash\\Hashes_Dates32.txt')
        execute_utils(
            'utils\\md5deep32.exe -u -t -r "%TEMP%\\*" >> artifacts\\hash\\Hashes_Dates32.txt')
    if check_sig_vt == '1':  # 굳이...
        execute_utils(
            'utils\\sigcheck_vt.exe -e -s -ct -h -v -accepteula "%ALLUSERSPROFILE%\\Start Menu\\*" >> artifacts\\hash\\sigcheck_startmenu_result.csv')
        execute_utils(
            'utils\\sigcheck_vt.exe -e -s -ct -h -v -accepteula "%ProgramData%\\Microsoft\\Windows\\Start Menu\\*" >> artifacts\\hash\\sigcheck_startmenu_result.csv')
        execute_utils(
            'utils\\sigcheck_vt.exe -e -s -ct -h -v -accepteula "%SystemDrive%\\Temp\\*" >> artifacts\\hash\\sigcheck_temp_result.csv')
        execute_utils(
            'utils\\sigcheck_vt.exe -e -s -ct -h -v -accepteula "%TEMP%\\*" >> artifacts\\hash\\sigcheck_temp_result.csv')


logFile = "NTFS_copy_log.log"
fls = "utils\\fls.exe"
icat = "utils\\icat.exe"


def listDrives():
    tmpDrives = []
    drives = []
    #fsCommand = subprocess.Popen(["fsutil", "fsinfo", "drives"], stdout=subprocess.PIPE)
    #fsOut = fsCommand.communicate()
    #tmpDrives = fsOut[0].split(":")
    dl = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    fsOut = ['%s:' % d for d in dl if os.path.exists('%s:' % d)]
    tmpDrives = fsOut[0].split(":")

    #del tmpDrives[0]
    #del tmpDrives[-1]
    # for line in tmpDrives:
    #    drives.append(line[-1])
    # return drives
    return fsOut


def flsResult(driveName, extraCode):
    driveName = "\\\\.\\"+driveName+":"
    if len(extraCode) > 0:
        flsCommand = subprocess.Popen(
            [fls, driveName, extraCode], stdout=subprocess.PIPE)
    else:
        flsCommand = subprocess.Popen([fls, driveName], stdout=subprocess.PIPE)
    flsOut = flsCommand.communicate()
    return flsOut[0]


def checkHDD(mainfls):
    m = re.search(r'\$MFT', mainfls)
    if m is not None:
        return 1
    else:
        return 0


def collectTriforces(mainfls, driveName, path, getlogfile):
    reExtend = ""
    extend = ""
    icatMFT = ""
    icatUsnJrnl = ""
    # MFT & LogFile
    try:
        icatMFT = icat+" \\\\.\\"+driveName+": 0 > "+path+"\\MFT.raw"
        logging.info(icatMFT)
        execute_utils(icatMFT)
        print('[*] parsing ' + path + '\\MFT.raw to MFT.csv')
        execute_utils('utils\\analyzemft_kor.exe -l -a -e -f ' +
                      path + "\\MFT.raw" + ' -o ' + path + '\\mft.csv')
        '''
		if os.path.isfile(path+"\\MFT.csv"):
			if os.path.getsize(path+"\\MFT.csv") > 1000 :
				os.remove(path+"\\MFT.raw")
		'''
        if getlogfile == "2":
            return 1
        icatLogFile = icat+" \\\\.\\"+driveName+": 2 > "+path+"\\LogFile.raw"
        logging.info(icatLogFile)
        execute_utils(icatLogFile)
    except:
        logging.error("MFT or LogFile Carving Failed")
    # UsnJrnl
    try:
        reExtend = re.search(r'(\d{1,5}-\d{1,5}-\d{1,5}):\t\$Extend', mainfls)
        if reExtend is not None:
            extend = reExtend.group(1)
            extendResult = flsResult(driveName, extend)
            reUsnJrnl = re.search(
                r'(\d{1,5}-\d{1,5}-\d{1,5}):\t\$UsnJrnl:\$J', extendResult)
            if reUsnJrnl is not None:
                usnJrnl = reUsnJrnl.group(1)
                icatUsnJrnl = icat+" \\\\.\\"+driveName+": "+usnJrnl+" > "+path+"\\usnJrnl.raw"
                logging.info(icatUsnJrnl)
                execute_utils(icatUsnJrnl)
            else:
                logging.warning("UsnJrnl Dosen't Exist")
    except:
        logging.error("UsnJrnl Carving Failed")


def copy_ntfs(getlogfile):
    extraCode = ""
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(message)s',
                        filename=logFile,
                        filemode='w')
    drives = []
    drives = listDrives()

    for line in drives:
        #print("line sub2", line)
        #print("line sub", line[0:1])
        line = line[0:1]
        wfolder = ""
        mainfls = flsResult(line, extraCode)
        mainfls = mainfls.decode('UTF-8')
        if checkHDD(mainfls) is 0:
            logging.info(line + ' is not HDD')
            pass
        else:
            wfolder = "artifacts\\drive_"+line
            if not os.path.exists(wfolder):
                os.makedirs(wfolder)
            collectTriforces(mainfls, line, wfolder, getlogfile)


def input_period(stime, etime):
    result = []
    print('[*] Collect Files From MFT (filesize < 20MB)')
    mac = ['create', 'modify', 'access']
    mftdir = ['artifacts\\drive_C\\', 'artifacts\\drive_D\\',
              'artifacts\\drive_E\\', 'artifacts\\drive_F\\', 'artifacts\\drive_G\\']

    for mactime in mac:
        print('\n[+] %s File (%s) ~ (%s)\n' %
              (mactime, str(stime), str(etime)))
        for i in mftdir:
            drivename = i.split('_')[1].replace('\\', ':')
            if os.path.isfile(i + 'mft.csv'):
                with open(i + 'mft.csv', 'rb') as f:
                    for mftline in f.readlines():
                        try:
                            x = mftline.split(',')
                            if x[3] == 'Folder' or x[2] == 'Inactive':
                                continue
                            fname = x[7].replace('/', '\\').replace('"', '')
                            fname = fname.encode('euc_kr')
                            if mactime == 'create':
                                fctime = x[12].replace(
                                    '=', '').replace('"', '')
                                copydir = 'create'
                            elif mactime == 'modify':
                                fctime = x[13].replace(
                                    '=', '').replace('"', '')
                                copydir = 'modify'
                            elif mactime == 'access':
                                fctime = x[14].replace(
                                    '=', '').replace('"', '')
                                copydir = 'access'
                            if fctime.find('-') and fctime.find(' ') > -1:
                                fileinformation_create = fctime.split(' ')[0]
                            elif fctime.find('-'):
                                fileinformation_create = fctime
                            else:
                                continue
                            fileinformation_create = datetime.datetime.strptime(
                                fileinformation_create, '%Y-%m-%d')  # %H:%M:%S')
                            if fileinformation_create >= stime and fileinformation_create <= etime:
                                with open('%s-%s_%s_mft.txt' % (str(stime).split(' ')[0], str(etime).split(' ')[0], copydir), 'ab') as wf:
                                    wf.write(str(fctime) + ':' +
                                             drivename + fname + '\n')
                                fullpath = drivename + fname
                                print(str(fctime) + ' : ' + fullpath)
                                if os.path.isfile(fullpath) and (os.path.getsize(fullpath) / (1024*1024) < 20) and fullpath not in result:
                                    if fullpath.find('exart') == -1:
                                        shutil.copy(fullpath, 'artifacts\\copy_from_mft\\%s\\%s' % (
                                            copydir, fullpath.replace(':', ';',).replace(' ', '_').replace('\\', '_')))
                                        result.append(fullpath)
                                        with open('copy_files_from_mft.txt', 'ab') as cf:
                                            cf.write(
                                                str(fctime) + ':' + drivename + fname + '\n')
                                else:
                                    with open('error_files_from_mft.txt', 'ab') as df:
                                        df.write(str(fctime) + ':' +
                                                 drivename + fname + '\n')
                        except Exception as err:
                            # print err
                            with open('error_files_from_mft.txt', 'ab') as ef:
                                ef.write(mftline)
                                continue
            else:
                continue


def timeck():
    start_time = time.localtime()
    check_localtime = time.localtime()
    time_check2 = str(check_localtime.tm_year) + '-' + str(check_localtime.tm_mon)+'-' + str(
        check_localtime.tm_mday)+' '+str(check_localtime.tm_hour)+':'+str(check_localtime.tm_min)
    return time_check2


###################
# Do the work main.
###################


def main():

    ########################
    # parameter init setting.
    ########################

    osspec = '0'
    workcontinue = '0'  # while 문 루프 판별
    sysmon_already = '0'
    check_mac = '0'
    if (len(sys.argv) == 2 and sys.argv[1] == 'linegames1!'):
        install_sysmon = '0'
        getlogfile = '0'
        getalllogfile = '0'
        getallexedllfile = '0'
        checkunsigned = '0'
        check_sig_vt = '2'
        check_mac = '0'
    else:
        print('[*] hey who are you??')
        print('[*] plz argument input password')
        sys.exit(1)
    print('\n############################################################################')
    print('[*] plz administrator cmd excute.')
    print('[*] Make sure you have enough capacity.')
    print('[*] exart ver 1.0   by shiro1628@line.games')
    print('############################################################################\n')

    while(workcontinue == '0'):
        workcontinue = input(
            '[+] Welcome, Are You Ready ? - 1 : yes   2 :  no  --> ')
        if workcontinue == '1' or workcontinue == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            workcontinue = '0'
    if workcontinue == '2':
        print('\n[*] see you sayonara.\n')
        sys.exit(1)

    # 필수 디렉토리 검증 필요
    # artifacts
    # artifacts\hash

    while(checkunsigned == '0'):
        checkunsigned = input(
            '[+] Check Unsigned File ? - 1 : yes   2 :  no  --> ')
        if checkunsigned == '1' or checkunsigned == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            checkunsigned = '0'

    while(install_sysmon == '0'):
        install_sysmon = input(
            '[+] install sysmon ? - 1 : yes   2 :  no  --> ')
        # sysmon install check
        if os.path.isfile('c:\\windows\\sysmon.exe') or os.path.isfile('c:\\windows\\sysmon64.exe'):
            print('[*] sysmon is already installed \n')
            sysmon_already = '1'
            break
        if install_sysmon == '1' or install_sysmon == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            install_sysmon = '0'

    while(getlogfile == '0'):
        getlogfile = input(
            '[+] usnjrl and logfiles getcha ? - 1 : yes   2 :  no  --> ')
        if getlogfile == '1' or getlogfile == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            getlogfile = '0'

    while(getalllogfile == '0'):
        getalllogfile = input(
            '[+] all log extension files getcha ? - 1 : yes   2 :  no  --> ')
        if getalllogfile == '1' or getalllogfile == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            getalllogfile = '0'

    while(getallexedllfile == '0'):
        getallexedllfile = input(
            '[+] all exe , dll extension files getcha ? - 1 : yes   2 :  no  --> ')
        if getallexedllfile == '1' or getallexedllfile == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            getallexedllfile = '0'

    while(check_mac == '0'):
        check_mac = input(
            '[+] files from MFT FNInfo getcha? (filesize < 20MB) - 1 : yes   2 :  no  --> ')
        if check_mac == '1':
            print('time format example : 1990-03-16')
            while(1):
                stime = input('input start time : ')
                if stime != '':
                    try:
                        stime = datetime.datetime.strptime(stime, '%Y-%m-%d')
                        break
                    except:
                        print(' [-] unknown time format')
                        continue
            while(1):
                etime = input('input end time : ')
                if etime != '':
                    try:
                        etime = datetime.datetime.strptime(etime, '%Y-%m-%d')
                        break
                    except:
                        print(' [-] unknown time format')
                        continue

        elif check_mac == '2':
            break
        else:
            print('\n[-] hey plz select 1 or 2\n')
            check_mac = '0'

    os_type = platform.release().lower()  # os_type 10
    if os_type.find('xp') > -1 or os_type.find('2003') > -1:
        #print("os version < 10")
        osspec = '1'
    else:
        #print("os version >= 10")
        osspec = '2'

    # osarchi = platform.machine() # osarchi AMD64
    osarchi = platform.machine()
    #print("os version < 10", osarchi.find('32'))
    if osarchi.find('64') > -1:
        osarch = '2'
    else:
        osarch = '1'
    output_file = 'shimcache.txt'  # arg
    do_local = True

    ############################
    # parameter init setting end.
    ############################

    # memdump(osarch)  # memory dump
    # ahnreportexe(osarch) # ahnreport execute

    print("[+] collect system time and Systeminfo")
    execute_utils(
        'echo %date% %time% > artifacts\\systeminfo.txt  & systeminfo >> artifacts\\systeminfo.txt')

    print("[+] collect DNSCache")
    execute_utils('ipconfig /displaydns > artifacts\\dnscache.txt')

    print("[+] collect BITS Service Job")
    # Stealth Falcon 등과 같은 악성코드들이 c&c 서버 등에 데이터를 보낼때 BITS 프로토콜을 이용하여 추가
    execute_utils(
        'bitsadmin.exe /list /allusers /verbose > artifacts\\bitsservicejob.txt')

    # 바이러스 토탈 등의 악성코드 사이트 활용을 위한 해쉬값 수집
    print("[+] Collect Hashes")
    #collect_hash(osarch, check_sig_vt)

    # sysmon install
    if install_sysmon == '1':
        print("[+] Monitoring Process and Network with sysmon (Wait a 30 seconds...)")
        if os_type.find('xp') > -1 or os_type.find('2003') > -1:
            execute_utils('utils\\sysmon_xp.exe -i -accepteula -h md5 -n -l')
        elif osarch == '1':
            execute_utils('utils\\sysmon.exe -i -accepteula -h md5 -n -l')
        else:
            execute_utils('utils\\sysmon64.exe -i -accepteula -h md5 -n -l')
        time.sleep(30)

    # everything search test
    print("[+] searching Test with everything")
    while(1):
        i = os.popen('utils\\es.exe "calc.exe"').read()
        if i.find('calc.exe') > -1:
            break
        else:
            print(' [-] everything scanning did not closed. plz wait')
            time.sleep(20)

    # iconcache 잘알려진 도구 등의 실행여부를 판별
    print('[+] collect IconCache.db ')
    f = os.popen('utils\\es.exe "iconcache.db"')
    for i in f.readlines():
        print(i)
        i = i.replace('\n', '')
        if len(i) > 10:
            try:
                if i.find('calc') == -1:
                    shutil.copy(i, 'artifacts\\iconcache\\%s' % i.replace(
                        ':', '_').replace(' ', '').replace('\\', '_'))
            except Exception as err:
                print(err)
                print('[+] Copying Error')
                continue

    # NTFS filesystem carving

    if getlogfile == '1':
        print("[+] Collect NTFS FILE SYSTEM MFT , USNJRNL , LOGFILE")
        try:
            copy_ntfs(getlogfile)
        except Exception as err:
            print('  [*] ', str(err).encode('utf-8'))
    else:
        print("[+] Collect  NTFS FILE SYSTEM MFT")
        try:
            copy_ntfs(getlogfile)
        except Exception as err:
            print('  [*] ', str(err).encode('utf-8'))

    print(
        "[+] Collect Registry , Prefetch , Eventlog , browser history , etc folder")
    # extract a $MFT
    #execute_utils('utils\\forecopy.exe -m artifacts')
    # extract event logs
    execute_utils('utils\\forecopy.exe -e artifacts')
    # extract prefetch & superfetch files
    execute_utils('utils\\forecopy.exe -p artifacts')
    # extract registry hive files
    execute_utils('utils\\forecopy.exe -g artifacts')
    # extract files of system32/drivers/etc
    execute_utils('utils\\forecopy.exe -t artifacts')
    # extract IE browser traces
    execute_utils('utils\\forecopy.exe -i artifacts')
    # extract Firefox browser traces
    execute_utils('utils\\forecopy.exe -x artifacts')
    # extract Chrome browser traces
    execute_utils('utils\\forecopy.exe -c artifacts')

    print('[+] collect Internet Cache Files')
    execute_utils('utils\\BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 1 /LoadIE1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 0 /sort ~2 /scomma artifacts\\webcache\\browsing-history.csv')

    execute_utils(
        'utils\\ChromeCacheView.exe /scomma artifacts\\webcache\\cache-chrome.csv')
    execute_utils(
        'utils\\ChromeCacheView.exe /copycache "" "" /CopyFilesFolder artifacts\\webcache\\cache-chrome /UseWebSiteDirStructure 0')
    execute_utils(
        'utils\\IECacheView.exe /scomma artifacts\\webcache\\cache-ie.csv')
    execute_utils(
        'utils\\IECacheView.exe /copycache "" "" /CopyFilesFolder artifacts\\webcache\\cache-ie /UseWebSiteDirStructure 0')
    execute_utils(
        'utils\\MozillaCacheView.exe /scomma artifacts\\webcache\\cache-mozilla.csv')
    execute_utils(
        'utils\\MozillaCacheView.exe /copycache "" "" /CopyFilesFolder artifacts\\webcache\\cache-mozilla /UseWebSiteDirStructure 0')

    print("[+] collect superfetch")
    if osarch == '1':
        execute_utils('utils\\crowdresponse.exe @superfetch > superfetch.xml')
    else:
        execute_utils(
            'utils\\crowdresponse64.exe @superfetch > superfetch.xml')
    execute_utils('utils\\crconvert.exe -f superfetch.xml -t')

    print("[+] Dumping Shim Cache data from the current system")
    execute_utils('shimcacheparser.exe -l -o shimcache.txt')
    cantcopyfiles = open('failed_copy_file_list.txt', 'w')

    print("[+] collect shimcache log")

    if os.path.isfile('shimcache.txt') == True:
        f = open('shimcache.txt', 'r')
        for i in f.readlines():
            try:
                i = i.decode('cp949').split(',')[2]
                i = i.replace('SYSVOL', 'c:').replace('\\??\\', '')
                replace_fname = i.replace(':', ';').replace(
                    ' ', '').replace('\\', '_')
                if i == 'Path':
                    continue
                if os.path.isfile('.\\artifacts\\collect_executed_files\\', replace_fname):
                    continue
                print(' [-] copying "%s"' % i)
                if os.path.getsize(i.encode('cp949')) / (1024*1024) > 20:
                    print(' [-] Exception - file size greater than 20MB : "%s"' %
                          (i.encode('cp949')))
                    cantcopyfiles.write(
                        ' [-] Exception - file size greater than 20MB : ' + ' - ' + i.encode('cp949') + '\n')
                    continue
                try:
                    if i.find('exart') == -1:
                        shutil.copy(i, 'artifacts\\collect_executed_files\\%s' % i.replace(
                            ':', ';').replace(' ', '').replace('\\', '_'))
                except Exception as err:
                    #print('  [*] ', str(err).encode('cp949'))
                    print('[+] Copying Error')
                    continue

            except Exception as err:
                print('  [*] ', str(err).encode('cp949'))
                continue
        f.close()
    else:
        print(" [-] shimcache.txt not found")

    print("[+] collect executed log")
    execute_utils(
        'utils\\ExecutedProgramsList.exe /scomma .\\utils\\executedlist.txt')
    if os.path.isfile('.\\utils\\executedlist.txt') == True:
        f = open('.\\utils\\executedlist.txt', 'rb')
        for i in f.readlines():
            try:
                # 한글 처리 문제
                i = i.decode('cp949').split(',')[0]
                replace_fname = i.replace(':', ';').replace(
                    ' ', '').replace('\\', '_').replace('\n', '')
                replace_fname = replace_fname.replace(
                    '.ApplicationCompany', '').replace('.FriendlyAppName', '')

                if i.find('Executed File') > -1:
                    continue
                if os.path.isfile('.\\artifacts\\collect_executed_files\\' + replace_fname):
                    continue
                print(' [-] copying "%s"' % i)
                if os.path.getsize(i) / (1024*1024) > 20:
                    print(
                        ' [-] Exception - file size greater than 20MB : "%s"' % (i.encode('cp949')))
                    cantcopyfiles.write(
                        "[-] Exception - file size greater than 20MB" + ' - ' + i + '\n')
                    continue
                if i.find('exart') == -1:
                    shutil.copy(i, 'artifacts\\collect_executed_files\\%s' % i.replace(
                        ':', '_').replace(' ', '').replace('\\', '_'))
                    os.rename('.\\artifacts\\collect_executed_files\\%s' % i.split(
                        '\\')[-1], '.\\artifacts\\collect_executed_files\\%s' % replace_fname)
            except Exception as err:
                print('[+] Copying Error')
                #print('  [*] ', str(err).encode('cp949'))
                continue
        f.close()
    else:
        print(" [-] executedlist.txt not found")

    print('[+] collect jump list')
    f = os.popen('utils\\es.exe file: "AutomaticDestinations\\"')
    for i in f.readlines():
        try:
            i = i.replace('\n', '')
            i = i.decode('cp949')

            if len(i) > 10:
                if i.find('exart') == -1:
                    print(i)
                    shutil.copy(i, 'artifacts\\jumplist\\%s' % i.replace(
                        ':', '_').replace(' ', '').replace('\\', '_'))
        except Exception as err:
            # print(str(err).encode('cp949'))
            print('[+] Copying Error')
            continue

    print('[+] collect rar , bat , ps1 , vbs , jsp , asp , aspx , php , war , cer , cdx , asa , ;.')
    f = os.popen('utils\\es.exe -r "(_jsp\\.java|\\.rar|\\.ps1|\\.vbs|\\.jsp|\\.asp|\\.aspx|\\.php|\\.war|\\.cer|\\.cdx|\\.asa|;\.(jpg|gif|bmp|png))$"')
    for i in f.readlines():
        try:
            i = i.replace('\n', '')
            i = i.decode('cp949')
            if os.path.isfile(i) and i.lower().find('winsxs') == -1 and i.lower().find('microsoft.net') == -1 and len(i.split('\\')[-1]) < 21 and len(i) < 100:
                if os.path.getsize(i) / (1024*1024) < 20:
                    if i.find('exart') == -1:
                        print(i)
                        shutil.copy(i, 'artifacts\\scriptfiles\\%s' %
                                    i.replace(':', '_').replace(' ', '').replace('\\', '_'))
        except Exception as err:
            # print(str(err).encode('cp949'))
            print('[+] Copying Error')
            continue

    # mft 검증 후 해당 시간대에 파일들이 존재한다면 파일 채증
    if check_mac == '1':
        try:
            input_period(stime, etime)
        except Exception as err:
            print(str(err))


if __name__ == "__main__":
    start_time = timeck()
    main()
    end_time = timeck()
    print('\n[ start time ] %s ~ [ end time ] %s' % (start_time, end_time))
