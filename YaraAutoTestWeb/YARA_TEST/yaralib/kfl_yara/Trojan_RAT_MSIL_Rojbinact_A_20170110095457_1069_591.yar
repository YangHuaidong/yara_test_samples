rule Trojan_RAT_MSIL_Rojbinact_A_20170110095457_1069_591 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/MSIL.Rojbinact.A"
		threattype = "rat"
		family = "Rojbinact"
		hacker = "None"
		refer = "F0DDBC5FADC4F8A9CE5D322C25F90543"
		description = "MSIL Rojbinact A RAT "
		comment = "None"
		author = "dengcong"
		date = "2016-11-22"
	strings:
		$f1 = "http://jach.me/lab/roj/index.php" nocase wide ascii
		$f2 = "taskeng" nocase wide ascii
		$f3 = "Task Scheduler Engine" nocase wide ascii
		$f4 = "7a17abbf-83c7-47be-a93a-7f00fef70a5a" nocase wide ascii
		$f5 = "PublicKeyToken=b77a5c561934e089" nocase wide ascii
		$f6 = "Task Scheduler Engine.exe" nocase
		$f7 = "C:\\Users\\yaszko\\Documents\\Visual Studio 2015\\Projects\\roj_bin\\roj_bin\\obj\\Debug\\Task Scheduler Engine.pdb"
		$f9 = "keystrokes"
		$f10 = "readKeyStrokes"
		$f11 = "Gmail" nocase wide ascii
		$f12 = "Facebook" nocase wide ascii
		$f14 = "button1" nocase wide ascii
		$a1 = "?action=get&id=" nocase wide ascii
		$a2 = "?action=post" nocase wide ascii
		$a3 = "3System.Resources.Tools.StronglyTypedResourceBuilder"
		$a5 = "SystemFunction005" nocase wide ascii

	condition:
		6 of them
}
