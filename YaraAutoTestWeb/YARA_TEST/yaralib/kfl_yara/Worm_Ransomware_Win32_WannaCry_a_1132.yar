rule Worm_Ransomware_Win32_WannaCry_a_1132
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.a"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Specific sample match for WannaCryptor"
	strings:		
        $taskdl = { 00 74 61 73 6b 64 6c }
        $taskse = { 00 74 61 73 6b 73 65 }
	condition:
		$taskdl at 3419456 and $taskse at 3422953
}