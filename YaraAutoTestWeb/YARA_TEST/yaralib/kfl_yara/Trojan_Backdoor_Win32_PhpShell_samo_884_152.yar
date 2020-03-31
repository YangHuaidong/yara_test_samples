rule Trojan_Backdoor_Win32_PhpShell_samo_884_152
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.samo"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "49ad9117c96419c35987aaa7e2230f63"
        comment = "None"
        date = "2018-11-13"
        description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
	strings:
		$s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
		$s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"
	condition:
		1 of them
}