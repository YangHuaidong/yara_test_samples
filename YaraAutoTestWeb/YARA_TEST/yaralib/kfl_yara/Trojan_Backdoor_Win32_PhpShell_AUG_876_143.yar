rule Trojan_Backdoor_Win32_PhpShell_AUG_876_143
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.AUG"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "12911b73bc6a5d313b494102abcf5c57"
        comment = "None"
        date = "2018-11-13"
        description = "Web Shell - file iMHaPFtp.php"
	strings:
		$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
		$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
	condition:
		1 of them
}