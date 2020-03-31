rule Trojan_Backdoor_Win32_PhpShell_redcod_881_149
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.redcod"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "5c1c8120d82f46ff9d813fbe3354bac5"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file PHPRemoteView.php"
	strings:
		$s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
		$s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
	condition:
		all of them
}