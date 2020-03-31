rule Trojan_Backdoor_Linux_Equation_magicjack_370_16
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.magicjack"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "07e7f2cf4adcd4d17bd337739ed05df1"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- magicjack_v1.1.0.0_client-1.1.0.0.py"
	strings:
		$x1 = "result = self.send_command(\"ls -al %s\" % self.options.DIR)" fullword ascii
		$x2 = "cmd += \"D=-l%s \" % self.options.LISTEN_PORT" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 80KB and 1 of them )
}