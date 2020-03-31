rule Trojan_Backdoor_Win32_BlackEnergy2_b_1068
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.BlackEnergy2.b"
		threattype = "ICS,Backdoor"
		family = "BlackEnergy2"
		hacker = "None"
		refer = "0af5b1e8eaf5ee4bd05227bf53050770"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
        $s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
        $s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
    condition:
        filesize < 1KB and 2 of them
}