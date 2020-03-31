rule Trojan_Hacktool_Win32_Laudanum_wbshelpre_875_536
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Laudanum.wbshelpre"
        threattype = "Hacktool"
        family = "Laudanum"
        hacker = "None"
        author = "copy"
        refer = "9329cd6f3fa15a9b7650966a04dd894f"
        comment = "http://laudanum.inguardians.com/"
        date = "2018-08-20"
        description = "Laudanum Injector Tools - file php-reverse-shell.php"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 15KB and all of them
}