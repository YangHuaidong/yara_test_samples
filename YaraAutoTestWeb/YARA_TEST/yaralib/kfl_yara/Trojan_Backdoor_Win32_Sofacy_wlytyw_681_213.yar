rule Trojan_Backdoor_Win32_Sofacy_wlytyw_681_213
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Sofacy.wlytyw"
        threattype = "backdoor"
        family = "Sofacy"
        hacker = "None"
        author = "balala"
        refer = "7c2b1de614a9664103b6ff7f3d73f83d"
        comment = "None"
        date = "2018-08-30"
        description = "None"
	strings:
        $s1 = "ASLIiasiuqpssuqkl713h" fullword wide
   
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and $s1
}