rule Trojan_Win32_KillDisk_fpd_70_655 
{

    meta:
        judge = "black"
		threatname = "Trojan[Downloader]/Win32.KillDisk.fpd"
		threattype = "Downloader"
		family = "KillDisk"
		hacker = "None"
		comment = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2015-05-14"
		author = "Florian Roth--DC"
		description = "Detects KillDisk malware from BlackEnergy" 
		refer = "66676deaa9dfe98f8497392064aefbab"
        score = 80
        super_rule = 1
        hash1 = "66676deaa9dfe98f8497392064aefbab"
        hash2 = "cd1aa880f30f9b8bb6cf4d4f9e41ddf4"
        hash3 = "72bd40cd60769baffd412b84acc03372"
        
        
    strings:
        $s0 = "%c:\\~tmp%08X.tmp" fullword ascii
        $s1 = "%s%08X.tmp" fullword ascii
        $s2 = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" fullword wide
        $s3 = "%ls_%ls_%ls_%d.~tmp" fullword wide

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 3 of them
}