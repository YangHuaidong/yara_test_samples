import "pe"
rule Trojan_Downloader_Win32_Sabres_e_228_366
{

    meta:
        judge = "black"
        threatname = "Trojan[downloader]/Win32.Sabres.e"
        threattype = "downloader"
        family = "Sabres"
        hacker = "None"
        author = "Florian Roth-mqx"
        refer = "f1059405feaaae373c59860fdec66fd0,75b713b8d54403c51317679b4038a6ff"
        comment = "None"
        date = "2018-07-19"
        description = "PassCV Malware mentioned in Cylance Report"

   strings:
      $x1 = "F:\\Excalibur\\Excalibur\\Excalibur\\" ascii
      $x2 = "bin\\oSaberSvc.pdb" ascii
      $s1 = "cmd.exe /c MD " fullword ascii
      $s2 = "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=0&rsv_idx=1&tn=baidu&wd=ip138" fullword wide
      $s3 = "CloudRun.exe" fullword wide
      $s4 = "SaberSvcB.exe" fullword wide
      $s5 = "SaberSvc.exe" fullword wide
      $s6 = "SaberSvcW.exe" fullword wide
      $s7 = "tianshiyed@iaomaomark1#23mark123tokenmarkqwebjiuga664115" fullword wide
      $s8 = "Internet Connect Failed!" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) and 5 of ($s*) ) ) or ( all of them )
}