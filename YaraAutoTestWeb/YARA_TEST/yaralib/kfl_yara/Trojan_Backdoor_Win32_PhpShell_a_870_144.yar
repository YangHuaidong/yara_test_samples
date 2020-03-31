rule Trojan_Backdoor_Win32_PhpShell_a_870_144
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.PhpShell.a"
        threattype = "Backdoor"
        family = "PhpShell"
        hacker = "None"
        author = "copy"
        refer = "e3b461f7464d81f5022419d87315a90d"
        comment = "None"
        date = "2018-11-13"
        description = "Web Shell - file a.php"
	strings:
		$s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
		$s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
		$s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
	condition:
		2 of them
}