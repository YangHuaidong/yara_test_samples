rule Trojan_Backdoor_Win32_Tzeebot_i_1134
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Tzeebot.i"
		threattype = "ICS,Backdoor"
		family = "Tzeebot"
		hacker = "None"
		refer = "b7ddb09bdc0d0eb39c364d9b9d6436cc"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-04-28"
		description = "None"
    strings:
		$s0 = "KeyLogger"
		$s1 = "keyboardHookProc"
		$s2 = "keyboardHookStruct"
		$s3 = "get_HookAllKeys"
		$s4 = "set_HookAllKeys"
    condition:
		all of them
}