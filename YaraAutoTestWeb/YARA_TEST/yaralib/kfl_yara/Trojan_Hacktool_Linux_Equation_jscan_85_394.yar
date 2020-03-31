rule Trojan_Hacktool_Linux_Equation_jscan_85_394
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Linux.Equation.jscan"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "967f48c928440688d80567927d2c10b3"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
	strings:
		$s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
		$s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii
	condition:
		filesize < 250KB and 1 of them
}