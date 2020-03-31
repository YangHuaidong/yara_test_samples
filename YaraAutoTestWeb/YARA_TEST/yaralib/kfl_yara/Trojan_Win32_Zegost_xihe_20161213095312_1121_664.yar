rule Trojan_Win32_Zegost_xihe_20161213095312_1121_664 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Zegost.xihe"
		threattype = "RAT|DDOS"
		family = "Zegost"
		hacker = "Xihe"
		refer = "c532e8a414e057917694affb5f56f890,8448382b5bc2e15fe596978d9f880d9e,715CB2F6481EC5EC99E5E56E38F01226"
		description = "None"
		comment = "None"
		author = "HuangYY"
		date = "2016-06-14"
	strings:
		$s0 = "\\Programs\\Startup\\Pc.exe"
		$s1 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor"
		$s2 = "\\%c%c%c%c%c.exe"
		$c0 = "Windows Test My Test 1.0"
		$c1 = "Windows Test My Test Server 1.0"
		$c2 = "This is Windows Test My Test Server 1.0"

	condition:
		($s0 and $s1 and $s2) or ($c0 and $c1 and $c2)
}
