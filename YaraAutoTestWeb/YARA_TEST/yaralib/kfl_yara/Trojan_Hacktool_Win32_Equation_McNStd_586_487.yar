rule Trojan_Hacktool_Win32_Equation_McNStd_586_487
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.McNStd"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "b8de1710e37e06dc3c8a970717886216"
        comment = "APT Equation Grou-https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
        date = "2018-08-13"
        description = "Equation Group hack tool set Mcl_NtMemory_Std "
   strings:
      $op1 = { 44 24 37 50 c6 44 24 38 72 c6 44 }
      $op2 = { 44 24 33 6f c6 44 24 34 77 c6 }
      $op3 = { 3b 65 c6 44 24 3c 73 c6 44 24 3d 73 c6 44 24 3e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}