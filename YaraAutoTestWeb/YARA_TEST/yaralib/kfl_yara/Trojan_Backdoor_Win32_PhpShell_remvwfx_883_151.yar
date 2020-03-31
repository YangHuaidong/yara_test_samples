rule Trojan_Backdoor_Win32_PhpShell_remvwfx_883_151
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.remvwfx"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "a24b7c492f5f00e2a19b0fa2eb9c3697"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file PHPRemoteView.php"
	strings:
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
		$s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
	condition:
		1 of them
}