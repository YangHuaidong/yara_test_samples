rule Trojan_Backdoor_Linux_PHP_NetFiMr_1038
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.PHP.NetFiMr"
        threattype = "Backdoor"
        family = "PHP"
        hacker = "None"
        author = "copy"
        refer = "acdbba993a5a4186fd864c5e4ea0ba4f"
        comment = "None"
        date = "2018-12-13"
        description = "Web Shell - file NetworkFileManagerPHP.php"
		score = 70
	strings:
		$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
	condition:
		all of them
}