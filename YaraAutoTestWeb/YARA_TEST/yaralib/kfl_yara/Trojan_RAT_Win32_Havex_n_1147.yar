rule Trojan_RAT_Win32_Havex_n_1147
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Havex.n"
		threattype = "ICS,RAT"
		family = "Havex"
		hacker = "None"
		refer = "8c8635986f9c770de821f941c28d722a"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-25"
		description = "Detects the Havex RAT malware"
	strings:
	    $s0 = {3C 73 75 70 70 6F 72 74 65 64 4F 53 20 49 64 3D 22 7B 65 32 30 31 31 34 35 37 2D 31 35 34 36 2D 34 33 63 35 2D 61 35 66 65 2D 30 30 38 64 65 65 65 33 64 33 66 30 7D 22 2F 3E}
		$s1 = {47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C}
		$s3 = {55 54 4E 2D 55 53 45 52 46 69 72 73 74 2D 4F 62 6A 65 63 74}
	condition:
	    all of them
}