rule Worm_Ransomware_Win32_WannaCry_Memory_1109
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.Memory"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"
	strings:		
        $s01 = "%08X.eky"
        $s02 = "%08X.pky"
        $s03 = "%08X.res"
        $s04 = "%08X.dky"
        $s05 = "@WanaDecryptor@.exe"
	condition:
		all of them
}