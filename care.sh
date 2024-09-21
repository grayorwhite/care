#!/bin/bash
CREATE_FILE="19501002_ghs".txt
echo > $CREATE_FILE 2>&1
# 01. DEFAULT_ID
echo "---------------01. DEFAULT_ID---------------" >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "lp:|uucp:|nuucp:" | wc -l` -eq 0 ]
    then
        echo "lp, uucp, nuucp ID not found ( GOOD )" >> $CREATE_FILE 2>&1
    else
        cat /etc/passwd | egrep "lp:|uucp:|nuucp:" >> $CREATE_FILE 2>&1   
fi
# 02. root_mgm start

echo "---------------02. root_mgm start---------------" >> $CREATE_FILE 2>&1
if [ `awk -F: '$3==0' /etc/passwd | wc -l` -eq 1 ]
    then
        echo "( GOOD )" >> $CREATE_FILE 2>&1
        awk -F: '$3==0 { print $1 " -> UID="$3 }' /etc/passwd >> $CREATE_FILE 2>&1
    else
        echo "( BAD )" >> $CREATE_FILE 2>&1 
fi
#.03.Passwd File Permission Check Start
echo "---------------03.Passwd File Permission Check Start---------------" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/passwd | awk '{print $1}' |grep ".rw-r--r--"|wc -l` -eq 1 ]
    then
       echo "Passwd file permission check Result : GOOD" >> $CREATE_FILE 2>&1
    else
        echo "Passwd file permission check Result : BAD" >> $CREATE_FILE 2>&1 
fi
#04. Group File Permission Check Start
echo "---------------04. Group File Permission Check Start---------------" >> $CREATE_FILE 2>&1
ls -alL /etc/group >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/group | awk '{print $1}' |grep ".rw-r--r--"|wc -l` -eq 1 ]
    then
        echo "group check Result : GOOD" >> $CREATE_FILE 2>&1
    else
        echo "group check Result : BAD" >> $CREATE_FILE 2>&1
fi
#05.Passwd Rule Check Start
echo "---------------05.Passwd Rule Check Start---------------" >> $CREATE_FILE 2>&1
        vuln5=`grep -v '#' /etc/login.defs | grep -i "PASS_MIN_LEN"`
	vuln6=`grep -v '#' /etc/login.defs | grep -i "PASS_MAX_DAYS"`
        vuln7=`grep -v '#' /etc/login.defs | grep -i "PASS_MIN_DAYS"`
#05.PASS_MIN_LEN, PASS_MAX_DAYS, PASS_MIN_DAYS CHECK RESULT
echo "---------------05.PASS_MIN_LEN, PASS_MAX_DAYS, PASS_MIN_DAYS CHECK RESULT---------------" >> $CREATE_FILE 2>&1
if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | awk '{print $2}'` -gt 7 ]
    then
        echo "( PASS_MIN_LEN passwd rule check result GOOD )" >> $CREATE_FILE 2>&1
    else
        echo "( PASS_MIN_LEN passwd rule check result BAD )" >> $CREATE_FILE 2>&1
fi
if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}'` -gt 70 ]
    then
        echo "( PASS_MAX_DAYS passwd rule check result BAD )" >> $CREATE_FILE 2>&1
    else
        echo "( PASS_MAX_DAYS passwd rule check result GOOD )" >> $CREATE_FILE 2>&1
fi
if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}'` -gt 0 ]
    then
        echo "( PASS_MIN_DAYS passwd rule check result GOOD )" >> $CREATE_FILE 2>&1
    else
        echo "( PASS_MIN_DAYS passwd rule check result BAD )" >> $CREATE_FILE 2>&1
fi
#06.Shell Check Start
echo "---------------06.Shell Check Start---------------" >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" | egrep -v "false|nologin" | wc -l` -eq 0 ]
    then
        echo "shell check Result : Good" >> $CREATE_FILE 2>&1
    else
        echo "shell check Result : BAD" >> $CREATE_FILE 2>&1
fi
#07.SU Check Start
echo "---------------07.SU Check Start---------------" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
    echo "(1) /etc/pam.d/su File" >> $CREATE_FILE 2>&1
    cat /etc/pam.d/su >> $CREATE_FILE 2>&1
else
    echo "/etc/pam.d/su File not found" >> $CREATE_FILE 2>&1
fi
if [ -f /etc/group ]
then
    echo "(2) /etc/group File" >> $CREATE_FILE 2>&1
    cat /etc/group >> $CREATE_FILE 2>&1
else
    echo "/etc/group File not found" >> $CREATE_FILE 2>&1
fi

#07 Result Start
echo "---------------07 Result Start---------------" >> $CREATE_FILE 2>&1
if [ `cat /etc/pam.d/su |grep -v 'trust' |grep 'pam-wheel.so' |grep 'use_uid' |grep -v '^#' |wc -l` -eq 0 ]
then
	echo "SU Check Result : BAD" >> $CREATE_FILE 2>&1
else
	echo "SU Check Result : GOOD" >> $CREATE_FILE 2>&1
fi
#08 Shadow Check Start
echo "---------------08 Shadow Check Start---------------" >> $CREATE_FILE 2>&1
ls -alL /etc/shadow >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/shadow | awk '{print $1}' | grep "..--------" | wc -l` -eq 1 ]
then
    echo "Shadow Check Result : GOOD" >> $CREATE_FILE 2>&1
else
    echo "Shadow Check Result : BAD" >> $CREATE_FILE 2>&1
fi
#09 Umask Check Start
echo "---------------09 UMASK Check Start---------------" >> $CREATE_FILE 2>&1
cat /etc/profile | grep -i umask >> $CREATE_FILE 2>&1
if [ `cat /etc/profile | grep -i "umask" | grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -gt 0 ]
then
    echo "UMASK Check Result : GOOD" >> $CREATE_FILE 2>&1
else
    echo "UMASK Check Result : BAD" >> $CREATE_FILE 2>&1
fi
#10 SetUID, SetGID Check Start
echo "---------------10 SetUID, SetGID Check Start---------------" >> $CREATE_FILE 2>&1
FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/sbin /lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"
for check_file in $FILES
do
    if [ -f $check_file ]
    then
        if [ `ls -alL $check_file | awk '{print $1}' | grep -i 's' | wc -l` -gt 0 ]
        then
            ls -alL $check_file | awk '{print $1}' | grep -i 's' >> set.txt
            ls -alL $check_file >> $CREATE_FILE
        else
            echo " " >> set.txt
        fi
    fi
done
echo "----------------[Result]--------------" >> $CREATE_FILE 2>&1
if [ `cat set.txt | awk '{print $1}' | grep -i 's' | wc -l` -gt 0 ]
    then
        echo "SetUID Check Result : BAD" >> $CREATE_FILE 2>&1
    else
        echo "SetUID Check Result : GOOD" >> $CREATE_FILE 2>&1
fi
rm -rf ./set.txt
#11. xinetd.conf Check Start
echo "---------------11 xinetd.conf Check Start---------------" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/xinetd.conf | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
then
    echo "xinetd.conf Check Result : GOOD" >> $CREATE_FILE 2>&1
else
    echo "xinetd.conf Check Result : BAD" >> $CREATE_FILE 2>&1
fi
#12. history Check Start
echo "---------------12 history Check Start---------------" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`

FILES=".sh_history      .bash_history   .history"
for dir in $HOMEDIRS
do
        for file in $FILES
        do
                if [ -f $dir/$file ]
                then
                        if [ `ls -dal $dir/$file | awk ' {print $1}' | grep "...------" | wc -l` -eq 1 ]
                then
                        echo "history Check Result : GOOD " >> history.txt
                        ls -dal $dir/$file >> $CREATE_FILE
                else
                        echo " history Check Result : BAD " >> history.txt
                        ls -dal $dir/$file >> $CREATE_FILE
fi
        else
                echo " history file not found" >> temp.txt
        fi
        done
done
echo "----------[Result]----------" >> $CREATE_FILE 2>&1
if [ `cat history.txt | grep "BAD" | wc -l` -eq 0 ]
then
                echo "history Check Result : GOOD " >> $CREATE_FILE
        else
                echo "history Check Result : BAD " >> $CREATE_FILE
fi
rm -rf ./history.txt
#13. crontab
echo "===== [ 13. crontab file permission check START] =====" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
cro="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"
for check_dir in $cro
do
                if [ -f $check_dir ]
                        then    ls -alL $check_dir >> $CREATE_FILE 2>&1
                        else    echo $check_dir " No Directory" >> $CREATE_FILE 2>&1
                fi
done
echo "" >> $CREATE_FILE 2>&1
echo ""> crontab.txt
echo "--------[CRONTAB RESULT START]--------" >> crontab.txt
echo ""> crontab.txt 2>&1
for check_dir in $cro
do
                if [ `ls -alL $check_dir | awk '{print $1}' | grep '.......w.' | wc -l` -eq 0 ]
                then
echo "Crontab file permission Check Result : GOOD" >> crontab.txt
                else
                        echo "Crontab file permission Check Result : BAD" >> crontab.txt
                fi
done
echo " " >> crontab.txt 2>&1
echo "----------[CRONTAB RESULT END]----------" >> crontab.txt
echo "" >> $CREATE_FILE 2>&1
if [ `cat crontab.txt | grep "BAD" | wc -l` -eq 0 ]
then
        echo "GOOD" >> $CREATE_FILE 2>&1
else
        echo "BAD" >> $CREATE_FILE 2>&1
fi
cat ./crontab.txt
rm -rf crontab.txt
#14. hosts permission check START
echo "======14. hosts permission check START ======" >> $CREATE_FILE 2>&1

if [ -f /etc/hosts ]
        then
                ls -alL /etc/hosts >> $CREATE_FILE 2>&1
        else
                echo "/etc/hosts file not found" >> $CREATE_FILE 2>&1
fi
echo "====== [Result] ======" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/hosts | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
        then
                echo "hosts permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo "hosts permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
echo "====== [hosts permission check END] ======" >> $CREATE_FILE 2>&1
echo "========== 15. issue permission check START ==========" >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
        then
                ls -alL /etc/issue >> $CREATE_FILE 2>&1
        else
                echo "/etc/issue file not found" >> $CREATE_FILE 2>&1
fi
echo "========== [Result] ==========" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/issue | awk '{print $1}' | grep '.....--.--' | wc -l` -eq 1 ]
        then
                echo "issue permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo "issue permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
echo "========== [issue permission check END] ==========" >> CREATE_FILE 2>&1
#15. issue permission check start
echo "========== 15. issue permission check START ==========" >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
        then
                ls -alL /etc/issue >> $CREATE_FILE 2>&1
        else
                echo "/etc/issue file not found" >> $CREATE_FILE 2>&1
fi
echo "========== [Result] ==========" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/issue | awk '{print $1}' | grep '.....--.--' | wc -l` -eq 1 ]
        then
                echo "issue permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo "issue permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
echo "========== [issue permission check END] ==========" >> CREATE_FILE 2>&1
#16. Home Directory permssion
echo "========== 16. Home Directory permission Check START ==========" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`

for dir in $HOMEDIRS
do
        ls -dal $dir | grep '\d..........' >> $CREATE_FILE 2>&1
done
echo " " >> $CREATE_FILE 2>&1
echo " " > home.txt
echo "----------[HOME DIR RESULT START]----------" >> home.txt 2>&1
for dir in $HOMEDIRS
do
        if [ -d $dir ]
        then
        if [ `ls -dal $dir | awk '{print $1}' | grep ".....--.--" | wc -l` -eq 1 ]
then echo "Home Directory permission Check Result : GOOD" >> home.txt
                else echo "Home Directory permission Check Result : BAD" >> home.txt
fi
        else
                echo "Home Directory permission Check Result : GOOD" >> home.txt
fi
done
echo " " >> home.txt 2>&1
echo "----------[HOME DIR RESULT END]----------" >> home.txt 2>&1
echo "==========[FINAL RESULT]==========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat home.txt | grep "BAD" | wc -l` -eq 0 ]
        then
                echo "Home Directory permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo " Home Directory permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
cat ./home.txt
rm -rf home.txt
echo " " >> $CREATE_FILE 2>&1

echo "========== 17. home directory configuration check START] ===== " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for dir in $HOMEDIRS
do
        for file in $FILES
        do
                if [ -f $dir/$file ]
                        then
                                ls -alL $dir/$file >> $CREATE_FILE 2>&1
                fi
        done
done
echo " " >> $CREATE_FILE 2>&1
for dir in $HOMEDIRS
do
        for file in $FILES
        do
        if [ -f $dir/$file ]
        then
        if [ `ls -alL $dir/$file | awk '{print $1}' | grep ".....--.--" | wc -l` -eq 1 ]
        then
                echo "Home Configuration Check Result : GOOD" >> homeconf.txt
        else
                echo "Home Configuration Check Result : BAD" >> homeconf.txt
        fi
        else
        echo "Home Configuration Check Result : GOOD" >> homeconf.txt
        fi
done
done

echo "========== [FINAL RESULT]==========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat homeconf.txt | grep "BAD" | wc -l` -eq 0 ]
        then
echo " Home Configuration Check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo " Home Configuration Check Result : BAD" >> $CREATE_FILE 2>&1
fi
cat ./homeconf.txt
rm -rf homeconf.txt
echo " " >> $CREATE_FILE 2>&1
echo "========== [FINAL END] ==========" >> $CREATE_FILE 2>&1
#18. Directory file permission
echo "====== [18. Directory file permission check START] ======" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>1
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"

for dir in $HOMEDIRS
do
        ls -dal $dir | grep '\d........' >> $CREATE_FILE 2>&1
done
echo " " >> $CREATE_FILE 2>&1
echo " " > dir.txt
echo "--------[18. Directory RESULT START]-------" >> dir.txt
echo " " >> dir.txt 2>&1
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"
for dir in $HOMEDIRS
do
if [ -d $dir ]
        then if [ `ls -dal $dir | awk '{print $1}' | grep "......-." | wc -l` -eq -1 ]
then echo "Directory permission Check Result : GOOD" >> dir.txt
                else echo "Directory permission Check Result : BAD" >> dir.txt

                fi
                else echo "Directory permission Check Result: GOOD" >> dir.txt
fi
done
echo " " >> dir.txt 2>&1
echo "--------[Directory RESULT END]-------" >> dir.txt
cat ./dir.txt

echo "===== [FINAL RESULT] ======" >> $CREATE_FILE 2>&1
echo " " >> CREATE_FILE 2>&1
if [ `cat dir.txt | grep "BAD" | wc -l` -eq 0 ]
        then
                echo "Directory file permission Check Result: GOOD" >> $CREATE_FILE 2>&1
        else
                echo "Directory file permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
cat ./dir.txt
rm -rf dir.txt
echo " " >> $CREATE_FILE 2>&1
echo "======[FINAL END]======" >> $CREATE_FILE 2>&1
#19. PATH Conf Check START
echo "====== [19. PATH Conf check START] ======" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `echo %PATH | grep "\. :" | wc -l` -eq 0 ]
        then
                echo "PATH Conf check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo "PATH Conf check Result : BAD" >> $CREATE_FILE 2>&1
fi
echo "====== [END] ======" >> $CREATE_FILE 2>&1
#20. ROOT Remote permission check START
echo "====== [20. ROOT Remote permission check START] ======" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]
then
        ls -alL /etc/pam.d/login >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " ======[FINAL RESULT] =====" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]
then
        if [ `ls -alL /etc/pam.d/login | awk '{print$1}' | grep '.......-.' | wc -l` -eq 0 ]
        then    echo "ROOT Remote file permission Check Result : BAD" >> $CREATE_FILE 2>&1
        else    echo "ROOT Remote file permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        fi
else
        echo "ROOT Remote file permission Check Result : GOOD" >> $CREATE_FILE 2>&1
fi
else echo "/etc/pam.d/login file not found" >> $CREATE_FILE 2>&1
fi
echo "====== [ ROOT Remote permission Check END] ======" >> $CREATE_FILE 2>&1
#21. ETC
echo "======= [21. ETC Files permission check START] =======" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
DIR744="/etc/rc*.d/* /etc/inittab /etc/syslog.conf /etc/snmp/conf/snmpd.conf"

echo " " >> $CREATE_FILE 2>&1
echo " " > etcfiles.txt

echo "======= [ETC Files RESULT START] =======" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
for check_dir in $DIR744
do
if [ -f $check_dir ]
        then
        ls -alL $check_dir >> $CREATE_FILE 2>&1
        if [ `ls -alL $check_dir | awk '{print $1}' | grep '........w.' | wc -l` -eq 0 ]
                then echo "ETC Files permission Check Result : GOOD" >> etcfiles.txt 2>&1
                else echo "ETC Files permission Check Result : BAD" >> etcfiles.txt 2>&1
        fi
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "======= [ETC Files RESULT END]=======" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "======= [FINAL RESULT] ======" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat etcfiles.txt | grep "BAD" | wc -l` -eq 0 ]
        then
                echo "ETC Files permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo "ETC Files permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
cat ./etcfiles.txt
rm -rf etcfiles.txt
echo " " >> $CREATE_FILE 2>&1
echo "======= [FINAL END] =======" >> $CREATE_FILE 2>&1
#22. NFS
echo "====== [22. NFS permission check Start] ======" >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
        then
                ls -alL /etc/exports >> $CREATE_FILE 2>&1
        else
                echo " /etc/exports file not found" >> $CREATE_FILE 2>&1
fi
echo "====== [NFS permission check Result] ======" >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
then
        if [ `ls -alL /etc/exports | awk '{print$1}' | grep '......-.' | wc -l` -eq 0 ]
        then    echo "NFS file permission Check Result : BAD" >> $CREATE_FILE 2>&1
        else    echo "NFS file permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        fi
else
        echo"NFS file permission Check Result : GOOD " >> $CREATE_FILE 2>&1
fi
echo "======[NFS file permission Check END] ======" >> $CREATE_FILE 2>&1
#23. service
echo "========== [23. Service File permission Check START] ==========" >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
then
        if [ `ls -alL /etc/services | awk '{print$1}' | grep "......-." | wc -l` -eq 0 ]
        then    echo " Service File permission Check Result : BAD" >> $CREATE_FILE 2>&1
        else    echo " Service File permission Check Result : GOOD" >> $CREATE_FILE 2>&1
        fi
else
        echo " Service File permission Check Result : GOOD" >> $CREATE_FILE 2>&1
fi
echo "========== [Service File permission Check END] ==========" >> $CREATE_FILE 2>&1
cat ./$CREATE_FILE
echo "==========[FINAL RESULT]==========" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
if [ `cat home.txt | grep "BAD" | wc -l` -eq 0 ]
        then
                echo "Home Directory permission Check Result: GOOD" >> $CREATE_FILE 2>&1
        else
                echo "Home Directory permission Check Result : BAD" >> $CREATE_FILE 2>&1
fi
cat ./home.txt
rm -rf home.txt
echo "" >> $CREATE_FILE 2>&1
#24. TMOUT
echo "===== [24. Session Time Out Check START] =====" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
        then
                cat /etc/profile | grep -i "TMOUT" | grep "=" >> $CREATE_FILE 2>&1
        else
                echo "/etc/profile not found" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "===== [FINAL RESULT] =====" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
 then
        if [ `cat /etc/profile | grep -v "#" | grep 'TMOUT.*[0-9]' | wc -l` -eq 1 ]
                then
                        echo "Session Time OuT Check Result : GOOD" >> $CREATE_FILE 2>&1
                else
echo "Session Time OuT Check Result : BAD" >> $CREATE_FILE 2>&1
fi
else            echo "Session Time Out Check Result : BAD" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo  "===== [FINAL END ] =====" >> $CREATE_FILE 2>&1
cat ./$CREATE_FILE
