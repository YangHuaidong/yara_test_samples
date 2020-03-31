rule Trojan_Hacktool_Linux_Equation_parsescan_86_400
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.parsescan"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "a802a29c58d753631412c56da9227384"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
	strings:
		$s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
		$s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
	condition:
		filesize < 250KB and 1 of them
}