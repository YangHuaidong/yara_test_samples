rule Trojan_Backdoor_Win32_Webshell_h4ntu_871_235
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Webshell.h4ntu"
        threattype = "Backdoor"
        family = "Webshell"
        hacker = "None"
        author = "copy"
        refer = "06ed0b2398f8096f1bebf092d0526137"
        comment = "None"
        date = "2018-11-13"
        description = "Web Shell - file h4ntu shell [powered by tsoi].php"
	strings:
		$s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
		$s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
		$s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
		$s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
	condition:
		all of them
}