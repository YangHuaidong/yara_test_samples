rule Trojan_Backdoor_Win32_PHP_i3lue_1041
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PHP.i3lue"
        threattype = "Backdoor"
        family = "PHP"
        hacker = "None"
        author = "copy"
        refer = "13f5c7a035ecce5f9f380967cf9d4e92"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file Private-i3lue.php"
		score = 70
	strings:
		$s8 = "case 15: $image .= \"\\21\\0\\"
	condition:
		all of them
}