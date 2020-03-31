rule Trojan_backdoor_Win32_PoseidonGroup_B_432_167 
{

    meta:
        judge = "black"
				threatname = "Trojan[backdoor]/Win32.PoseidonGroup.B"
				threattype = "backdoor"
				family = "PoseidonGroup"
				hacker = "None"
				comment = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
				date = "2016-04-12"
				author = "Florian Roth-DC"
				description = "Detects Poseidon Group - Malicious Word Document" 
				refer = "05da1b2681a3997a7cc55eeef9c0ea37"

    strings:
        $s1 = "c:\\cmd32dll.exe" fullword ascii

    condition:
        uint16(0) == 0xcfd0 and filesize < 500KB and all of them
}
