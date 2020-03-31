rule Trojan_Backdoor_Win32_PhpShell_PHVayv_880_148
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.PHVayv"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "35fb37f3c806718545d97c6559abd262"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file file PH Vayv.php"
	strings:
		$s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
		$s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
	condition:
		1 of them
}