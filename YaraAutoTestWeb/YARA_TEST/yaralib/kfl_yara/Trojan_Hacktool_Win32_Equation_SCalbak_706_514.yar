rule Trojan_Hacktool_Win32_Equation_SCalbak_706_514
{
    meta:
        judge = "black"
        threatname = "Trojan[Hacktool]/Win32.Equation.SCalbak"
        threattype = "Hacktool"
        family = "Equation"
        hacker = "None"
        author = "Florian Roth-copy"
        refer = "d6f6ca5ef82f6a8f346bdc6c2e4b10e1"
        comment = "APT Equation Grou-https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
        date = "2018-09-03"
        description = "Equation Group hack tool set SetCallback "
   strings:
      $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
      $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}