rule Trojan_Backdoor_Win32_RemoteManipulator_bis_20170331144833_942_194 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.RemoteManipulator.bis"
		threattype = "BackDoor"
		family = "RemoteManipulator"
		hacker = "None"
		refer = "d9fe2bb70fe298181906e52cd2d648f7"
		description = "None"
		comment = "None"
		author = "djw"
		date = "2017-03-21"
	strings:
		$s0 = "services.pdb"
		$s1 = "I_NetServerSetServiceBits"
		$s2 = "tserv.exe"
		$s3 = "irmshalw"
		$s4 = "imbfusv"
		$s5 = "restartapp.exe"
		$s6 = "NtControlPipe"

	condition:
		4 of them
}
