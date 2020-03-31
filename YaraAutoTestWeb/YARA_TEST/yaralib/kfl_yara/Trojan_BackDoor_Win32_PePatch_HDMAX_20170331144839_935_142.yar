rule Trojan_BackDoor_Win32_PePatch_HDMAX_20170331144839_935_142 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.PePatch.HDMAX"
		threattype = "BackDoor"
		family = "PePatch"
		hacker = "None"
		refer = "7fcaead624f97fc98198c52b08ee19a0"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2017-03-22"
	strings:
		$s0 = "HDMAX"
		$s1 = "shbscdacbess Resoter"
		$s2 = "Beep.sys"
		$s3 = "pipe\\net\\NtControlPipe"	nocase wide ascii
		$s4 = "safeboot"			nocase wide ascii
		$s5 = "BootVerificationProgram"		nocase wide ascii
		$s6 = "Mdfsler.exe"
		$s7 = "%sdfie.exe"

	condition:
		4 of them
}
