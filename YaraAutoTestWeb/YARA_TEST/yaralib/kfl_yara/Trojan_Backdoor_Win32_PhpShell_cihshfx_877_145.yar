rule Trojan_Backdoor_Win32_PhpShell_cihshfx_877_145
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.cihshfx"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "3823ac218032549b86ee7c26f10c4cb5"
        comment = "None"
        date = "2018-11-20"
        description = "Web Shell - file cihshell_fix.php"
	strings:
		$s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
		$s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
	condition:
		1 of them
}