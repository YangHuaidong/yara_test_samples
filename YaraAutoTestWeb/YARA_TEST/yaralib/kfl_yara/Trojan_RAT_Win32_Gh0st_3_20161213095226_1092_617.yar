rule Trojan_RAT_Win32_Gh0st_3_20161213095226_1092_617 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.Gh0st.3"
		threattype = "rat"
		family = "Gh0st"
		hacker = "None"
		refer = "18CB5A2D334A87512779FA50A8864C84,58BDAEB6D4D5997FD2F29C6D7F5F9750,BF0110E31E8DB75FFF3824B453357674,FF6DECEFDE1FE4E733726A67B4ACBD9A,40A347B624F25D55171AA5F560119425,979074DBF2D1B360ADCA6130F9A4C9E8,429DB3F161758E0116AFB3C79B4E4DE1"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2016-09-01"
	strings:
		$s0 = "WinSta0"
		$s1 = "/c del"
		$s2 = "COMSPEC"
		$s3 = "DeleteMe"
		$s4 = "ProcessorNameString"
		$s5 = "iexplore.exe"
		$s6 = "CentralProcessor"
		$s7 = "SYSTEM\\CurrentControlSet\\Services\\%s"

	condition:
		all of them
}
