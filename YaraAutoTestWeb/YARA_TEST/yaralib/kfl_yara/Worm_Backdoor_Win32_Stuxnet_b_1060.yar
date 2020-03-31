rule Worm_Backdoor_Win32_Stuxnet_b_1060
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Stuxnet.b"
		threattype = "ICS,Backdoor"
		family = "Stuxnet"
		hacker = "None"
		refer = "1e17d81979271cfa44d471430fe123a5"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s1 = "\\SystemRoot\\System32\\hal.dll" fullword wide
        $s2 = "http://www.jmicron.co.tw0" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 70KB and all of them
}