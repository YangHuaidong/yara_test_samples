rule Trojan_Hacktool_Win32_Laudanum_cmdwar_873_534
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Laudanum.cmdwar"
        threattype = "Hacktool"
        family = "Laudanum"
        hacker = "None"
        author = "copy"
        refer = "b3772aa5c05bc7542fcf8e01bfe18b06"
        comment = "http://laudanum.inguardians.com/"
        date = "2018-08-20"
        description = "Laudanum Injector Tools - file cmd.war"
	strings:
		$s0 = "cmd.jsp}" fullword ascii
		$s1 = "cmd.jspPK" fullword ascii
		$s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
		$s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
		$s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
	condition:
		uint16(0) == 0x4b50 and filesize < 2KB and all of them
}