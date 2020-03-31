rule Trojan_Rootkit_Win32_Stuxnet_ttdyxy_715_637
{
    meta:
        judge = "black"
        threatname = "Trojan[Rootkit]/Win32.Stuxnet.ttdyxy"
        threattype = "Rootkit"
        family = "Stuxnet"
        hacker = "None"
        author = "balala"
        refer = "cc1db5360109de3b857654297d262ca1,f8153747bae8b4ae48837ee17172151e"
        comment = "None"
        date = "2018-09-05"
        description = "None"
	strings:
        $x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
        $x2 = "MRxCls.sys" fullword wide
        $x3 = "MRXNET.Sys" fullword wide
   
    condition:
        ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )

}