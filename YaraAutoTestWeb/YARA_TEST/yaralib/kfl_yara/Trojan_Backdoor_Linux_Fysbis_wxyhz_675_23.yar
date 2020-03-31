rule Trojan_Backdoor_Linux_Fysbis_wxyhz_675_23
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Fysbis.wxyhz"
        threattype = "backdoor"
        family = "Fysbis"
        hacker = "None"
        author = "balala"
        refer = "075b6695ab63f36af65f7ffd45cccd39,364ff454dcf00420cff13a57bcb78467"
        comment = "None"
        date = "2018-08-30"
        description = "None"
	strings:
        $x1 = "Your command not writed to pipe" fullword ascii
        $x2 = "Terminal don`t started for executing command" fullword ascii
        $x3 = "Command will have end with \\n" fullword ascii
        $s1 = "WantedBy=multi-user.target' >> /usr/lib/systemd/system/" fullword ascii
        $s2 = "Success execute command or long for waiting executing your command" fullword ascii
        $s3 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" fullword ascii
        $s4 = "rm -f /usr/lib/systemd/system/" fullword ascii
        $s5 = "ExecStart=" fullword ascii
        $s6 = "<table><caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 500KB and 1 of ($x*) ) or ( 1 of ($x*) and 3 of ($s*) )

}