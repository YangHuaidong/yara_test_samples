rule Worm_Backdoor_Win32_Stuxnet_dll_1063
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Stuxnet.dll"
		threattype = "ICS,Backdoor"
		family = "Stuxnet"
		hacker = "None"
		refer = "d24f522d4c40c33cb92f226a255c5bd0"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and $s1
}