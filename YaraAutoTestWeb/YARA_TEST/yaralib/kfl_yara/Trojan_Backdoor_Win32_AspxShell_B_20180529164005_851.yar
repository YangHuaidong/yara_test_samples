rule Trojan_Backdoor_Win32_AspxShell_B_20180529164005_851 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.AspxShell.B"
		threattype = "BackDoor"
		family = "AspxShell"
		hacker = "None"
		refer = "CF56CB65C4E5B4D7794147DAEED0BF66,0A40E22A4FFAD11B7EC038ACBB665D36"
		description = "ASPXSpy detection. It might be used by other fraudsters"
		comment = "None"
		author = "mqx"
		date = "2018-04-27"
	strings:
		$str1 = "ASPXSpy" nocase wide ascii
		$str2 = "IIS Spy" nocase wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii

	condition:
		any of ($str*)
}
