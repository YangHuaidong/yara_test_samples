rule Trojan_DDoS_Win32_StormDDoS_4_20161213095149_1026_321 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.4"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "Guiying workstation"
		refer = "6a846d1210c51c637f254b45cb937c79,be34f96df260d2823ef0345ee81f940e,72363EBC436462A268F2C54A37080362"
		description = "IM_ServStart"
		comment = "None"
		author = "HuangYY"
		date = "2016-06-14"
	strings:
		$s0 = "F:\\g1fd.exe"
		$s1 = "E:\\g1fd.exe"
		$s2 = "D:\\g1fd.exe"
		$s3 = "C:\\g1fd.exe"
		$c0 = ".Net CLR"
		$c1 = "Microsoft .Net Framework COM+ Support"
		$c2 = "Microsoft .NET COM+ Integration with SOAP"

	condition:
		($s0 and $s1 and $s2 and $s3) or ($c0 and $c1 and $c2)
}
