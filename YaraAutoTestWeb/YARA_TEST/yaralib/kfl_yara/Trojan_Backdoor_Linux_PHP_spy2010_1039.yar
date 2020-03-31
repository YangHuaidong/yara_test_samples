rule Trojan_Backdoor_Linux_PHP_spy2010_1039
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.PHP.spy2010"
        threattype = "Backdoor"
        family = "PHP"
        hacker = "None"
        author = "copy"
        refer = "14ae0e4f5349924a5047fed9f3b105c5"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file phpspy2010.php"
		score = 70
	strings:
		$s3 = "eval(gzinflate(base64_decode("
		$s5 = "//angel" fullword
		$s8 = "$admin['cookiedomain'] = '';" fullword
	condition:
		all of them
}