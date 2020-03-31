rule Worm_Ransomware_Win32_WannaCry_Decryptor_1112
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.Decryptor"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detection for common strings of WannaDecryptor"
	strings:		
        $id1 = "taskdl.exe"
        $id2 = "taskse.exe"
        $id3 = "r.wnry"
        $id4 = "s.wnry"
        $id5 = "t.wnry"
        $id6 = "u.wnry"
        $id7 = "msg/m_"
	condition:
		3 of them
}