rule Trojan_BackDoor_Win32_Revird_svc_20161213095127_943_195 
{
	meta:
		judge = "black"
		threatname = "Trojan[BackDoor]/Win32.Revird.svc"
		threattype = "rat"
		family = "Revird"
		hacker = "None"
		refer = "91e92d7261f421db3d4ee7b57636aa6f"
		description = "CommentCrew-threat-apt1"
		comment = "None"
		author = "djw,AlienVault Labs"
		date = "2016-09-01"
	strings:
		$dll1 = "nwwwks.dll" wide ascii
		$dll2 = "rdisk.dll" wide ascii
		$dll3 = "skeys.dll" wide ascii
		$dll4 = "SvcHost.DLL.log" wide ascii
		$svc1 = "InstallService" wide ascii
		$svc2 = "RundllInstallA" wide ascii
		$svc3 = "RundllUninstallA" wide ascii
		$svc4 = "ServiceMain" wide ascii
		$svc5 = "UninstallService" wide ascii

	condition:
		1 of ($dll*) and 2 of ($svc*)
}
