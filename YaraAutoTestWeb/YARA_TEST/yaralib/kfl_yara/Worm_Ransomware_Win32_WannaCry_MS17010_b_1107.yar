rule Worm_Ransomware_Win32_WannaCry_MS17010_b_1107
{
	meta:
		judge = "black"
		threatname = "Worm[Ransomware]/Win32.WannaCry.MS17010.b"
		threattype = "ICS,Ransomware"
		family = "WannaCry"
		hacker = "None"
		refer = "84c82835a5d21bbcf75a61706d8ab549"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-05-10"
		description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"
	strings:		
        $s01 = "__TREEID__PLACEHOLDER__" ascii
        $s02 = "__USERID__PLACEHOLDER__@" ascii
        $s03 = "SMB3"
        $s05 = "SMBu"
        $s06 = "SMBs"
        $s07 = "SMBr"
        $s08 = "%s -m security" ascii
        $s09 = "%d.%d.%d.%d"
        $payloadwin2000_2195 =
"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"
        $payload2000_50 =
"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"
condition:
        all of them
}