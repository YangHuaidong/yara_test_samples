rule Trojan_DDoS_Win32_ChickenMM_dos_20161213095145_1001_293 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.ChickenMM.dos"
		threattype = "DDOS"
		family = "ChickenMM"
		hacker = "None"
		refer = "9ab92230abfaf44bc991812c93d5b056"
		description = "Win32-variant of Chicken ident for both dropper and dropped file"
		comment = "None"
		author = "djw,Jason Jones <jasonjones@arbor.net>"
		date = "2016-12-01"
	strings:
		$pdb1 = "\\Chicken\\Release\\svchost.pdb"
		$pdb2 = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"
		$str1 = "dm1712/`jvpnpkte/bpl"
		$str2 = "fake.cf"
		$str3 = "8.8.8.8"
		$str4 = "Processor(%d)\\"
		$str5 = "DbProtectSupport"
		$str6 = "InstallService NPF %d"
		$str7 = "68961"
		$str8 = "InstallService DbProtectSupport %d"
		$str9 = "C:\\Program Files\\DbProtectSupport\\npf.sys"

	condition:
		($pdb1 or $pdb2) and 5 of ($str*)
}
