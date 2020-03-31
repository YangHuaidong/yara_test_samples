rule Trojan_Backdoor_Linux_Equation_wtelnet_76_21
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.wtelnet"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "f267794f287deca1069236df6d2ca71c"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-09"
        description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
	strings:
		$s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
		$s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
		$s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 4KB and 1 of them )
}