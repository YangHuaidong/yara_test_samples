rule Trojan_Backdoor_Win32_PhpShell_SimAtt_885_153
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.SimAtt"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "089ff24d978aeff2b4b2869f0c7d38a3"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
	strings:
		$s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
		$s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
	condition:
		1 of them
}