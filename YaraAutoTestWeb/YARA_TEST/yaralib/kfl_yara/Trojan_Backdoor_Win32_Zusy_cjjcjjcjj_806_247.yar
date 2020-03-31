rule Trojan_Backdoor_Win32_Zusy_cjjcjjcjj_806_247
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Zusy.cjjcjjcjj"
        threattype = "Backdoor"
        family = "Zusy"
        hacker = "None"
        author = "balala"
        refer = "f898eef9dfa04820bb2f798e063645a7,b4790618672197cab31681994bbc10a4,1a2b18cb40d82dc279eb2ef923c3abd0"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $x0 = "Users\\Wool3n.H4t\\"
        $x1 = "C-CPP\\CWoolger"
        $x2 = "NTSuser.exe" fullword wide
        $s1 = "107.6.181.116" fullword wide
        $s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
        $s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
        $s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
        $s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
        $s6 = "wlg.dat" fullword
        $s7 = "woolger" fullword wide
        $s8 = "[Enter]" fullword
        $s9 = "[Control]" fullword
    condition:
        ( 1 of ($x*) and 2 of ($s*) ) or ( 6 of ($s*) )
}