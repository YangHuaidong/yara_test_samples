rule Trojan_Hacktool_Linux_Equation_jparsescan_84_393
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.jparsescan"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d638c10905ef871f8dbede33ec89719d"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
	strings:
		$s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
		$s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
	condition:
		( filesize < 40KB and 1 of them )
}