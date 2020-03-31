rule Trojan_Rootkit_Win32_Winnti_wulahahha_813_643
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Winnti.wulahahha"
        threattype = "Rootkit"
        family = "Winnti"
        hacker = "None"
        author = "balala"
        refer = "2c85404fe7d1891fd41fcee4c92ad305,326cbe7a0eed991ef7fc3d59d7728c6f"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $s1 = "Guangzhou YuanLuo Technology Co." ascii
        $s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
        $s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}