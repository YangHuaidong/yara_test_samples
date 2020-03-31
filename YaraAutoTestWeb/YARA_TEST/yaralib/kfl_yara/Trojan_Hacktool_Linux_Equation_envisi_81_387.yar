rule Trojan_Hacktool_Linux_Equation_envisi_81_387
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.envisi"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "49c27aee705431601fb7b9d6dffdea93"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file envisioncollision"
	strings:
		$x1 = "mysql \\$D --host=\\$H --user=\\$U --password=\\\"\\$P\\\" -e \\\"select * from \\$T" fullword ascii
		$x2 = "Window 3: $0 -Uadmin -Ppassword -i127.0.0.1 -Dipboard -c\\\"sleep 500|nc" fullword ascii
		$s3 = "$ua->agent(\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\");" fullword ascii
		$s4 = "$url = $host . \"/admin/index.php?adsess=\" . $enter . \"&app=core&module=applications&section=hooks&do=install_hook\";" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 20KB and 1 of ($x*) ) or ( 2 of them )
}