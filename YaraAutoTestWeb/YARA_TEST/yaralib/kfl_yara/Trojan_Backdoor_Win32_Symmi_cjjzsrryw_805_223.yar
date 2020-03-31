rule Trojan_Backdoor_Win32_Symmi_cjjzsrryw_805_223
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Symmi.cjjzsrryw"
        threattype = "Backdoor"
        family = "Symmi"
        hacker = "None"
        author = "balala"
        refer = "ee41e7c97f417b07177ea420afe510a1"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $s1 = "Cannot execute (%d)" fullword ascii
        $s16 = "SvcName" fullword ascii
    condition:
        all of them
}