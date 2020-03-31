rule Worm_Backdoor_Win32_Stuxnet_c_1062
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Stuxnet.c"
		threattype = "ICS,Backdoor"
		family = "Stuxnet"
		hacker = "None"
		refer = "cc1db5360109de3b857654297d262ca1"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
        $x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
        $x2 = "MRxCls.sys" fullword wide
        $x3 = "MRXNET.Sys" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )
}