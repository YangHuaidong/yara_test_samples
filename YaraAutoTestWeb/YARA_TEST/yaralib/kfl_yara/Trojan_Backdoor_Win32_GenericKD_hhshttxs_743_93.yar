rule Trojan_Backdoor_Win32_GenericKD_hhshttxs_743_93
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.GenericKD.hhshttxs"
        threattype = "Backdoor"
        family = "GenericKD"
        hacker = "None"
        author = "balala"
        refer = "60bcc6bc746078d81a9cd15cd4f199bb"
        comment = "None"
        date = "2018-09-27"
        description = "None"
	strings:
        $ = {81 FA FF 00 00 00 0F B6 C2 0F 46 C2 0F B6 0C 04 48 03 CF 0F B6 D1 8A 0C 14 8D 50 01 43 32 0C 13 41 88 0A 49 FF C2 49 83 E9 01}
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}