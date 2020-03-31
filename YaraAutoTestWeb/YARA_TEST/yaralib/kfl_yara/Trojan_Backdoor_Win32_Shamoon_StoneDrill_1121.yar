rule Trojan_Backdoor_Win32_Shamoon_StoneDrill_1121
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Shamoon.StoneDrill"
		threattype = "ICS,Backdoor"
		family = "Shamoon"
		hacker = "None"
		refer = "d01781f1246fd1b64e09170bd6600fe1,ac3c25534c076623192b9381f926ba0d"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "None"
    strings:
        $code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF
30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}
    condition:
        uint16(0) == 0x5A4D and $code and filesize < 5000000
}