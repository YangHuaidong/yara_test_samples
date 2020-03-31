rule Trojan_Backdoor_Win32_TSGeneric_hlhlbydn_687_230
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.TSGeneric.hlhlbydn"
        threattype = "Backdoor"
        family = "TSGeneric"
        hacker = "None"
        author = "balala"
        refer = "6093505c7f7ec25b1934d3657649ef07,2be2ac65fd97ccc97027184f0310f2f3"
        comment = "None"
        date = "2018-09-06"
        description = "None"
	strings:
        $s0 = "svchostdllserver.dll" fullword ascii 
        $s1 = "Lpykh~mzCCRv|mplpykCCHvq{phlCC\\jmmzqkIzmlvpqCC" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and all of them

}