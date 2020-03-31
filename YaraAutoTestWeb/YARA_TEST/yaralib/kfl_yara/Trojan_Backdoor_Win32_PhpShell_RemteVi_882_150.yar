rule Trojan_Backdoor_Win32_PhpShell_RemteVi_882_150
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.RemteVi"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "29420106d9a81553ef0d1ca72b9934d9"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file PHPRemoteView.php"
	strings:
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
	condition:
		1 of them
}