rule Trojan_RAT_Win32_Binder_20170811104328_966 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Binder"
		threattype = "rat"
		family = "Binder"
		hacker = "None"
		refer = "b55ea4dc4d2bda7c3d3de9a279d58b2d"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2017-07-27"
	strings:
		$s0 = "DirectX jrq"
		$s1 = "DUB.exe.exe"
		$s3 = "SinaShow.exe"
		$s4 = "UnThreat.exe"
		$s5 = "K7TSecurity.exe"
		$s6 = "PSafeSysTray.exe"
		$s7 = "360tray.exe"
		$s8 = "QQPCRTP.exe"
		$s9 = "SPIDer.exe"

	condition:
		all of them
}
