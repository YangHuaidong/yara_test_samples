rule Worm_Ransomware_Win32_WannaCry_MS17010_a_1106
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.MS17010.a"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Worm exploiting MS17-010 and dropping WannaCry Ransomware"
	strings:		
		$ms17010_str1="PC NETWORK PROGRAM 1.0"
		$ms17010_str2="LANMAN1.0"
		$ms17010_str3="Windows for Workgroups 3.1a"
		$ms17010_str4="__TREEID__PLACEHOLDER__"
		$ms17010_str5="__USERID__PLACEHOLDER__"
		$wannacry_payload_substr1 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
		$wannacry_payload_substr2 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
		$wannacry_payload_substr3 = "tpGFEoLOU6+5I78Toh/nHs/RAP"
	condition:
		all of them
}