rule Trojan_RAT_Win32_Havex_PHP_1057
{
    meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.Memdump"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "8065674de8d79d1c0e7b3baf81246e7d"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "Detects the PHP server component of the Havex RAT"
    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"
    condition:
        all of them
} 