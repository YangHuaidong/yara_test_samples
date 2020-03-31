rule Trojan_Backdoor_Win32_NetWiredRC_a_20171226145139_869 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.NetWiredRC.a"
		threattype = "BackDoor"
		family = "NetWiredRC"
		hacker = "None"
		refer = "6F1D5C57B3B415EDC3767B079999DD50"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-12-13"
	strings:
		$s0 = "C:\\Users\\pzh\\Desktop\\tools tekide\\tools tekide\\" nocase wide ascii
		$s1 = "Rfc2898DeriveBytes" nocase wide ascii
		$s2 = "Bitmap" nocase wide ascii
		$s3 = "File.exe" nocase wide ascii
		$s4 = "FileApp.exe" nocase wide ascii

	condition:
		4 of them
}
