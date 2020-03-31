rule Trojan_Backdoor_Linux_Equation_telex_373_19
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Linux.Equation.telex"
        threattype = "Backdoor"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "9e5316a64f320f9486e6723a166a9efc"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-07-02"
        description = "Equation Group hack tool leaked by ShadowBrokers- telex"
	strings:
		$x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
		$x2 = "target is not vulnerable. exiting" fullword ascii
		$s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
		$s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}