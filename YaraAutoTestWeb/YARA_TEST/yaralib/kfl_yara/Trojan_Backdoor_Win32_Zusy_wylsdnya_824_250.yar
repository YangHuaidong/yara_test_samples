rule Trojan_Backdoor_Win32_Zusy_wylsdnya_824_250
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Zusy.wylsdnya"
        threattype = "Backdoor"
        family = "Zusy"
        hacker = "None"
        author = "bala"
        refer = "ae06248ab3c02e1c2ca9d53b9a155199"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
		$a = { 52 59 47 40 4A 41 59 5D 52 00 00 00 FF FF FF FF }
		$b = { 06 00 00 00 52 59 47 40 40 5A 00 00 FF FF FF FF }
		$c = { 0A 00 00 00 52 5C 4B 4D 57 4D 42 4B 5C 52 00 00 }
		$d = { FF FF FF FF 0A 00 00 00 52 5D 57 5D 5A 4B 43 70 }
		$e = { 3F 52 00 00 FF FF FF FF 06 00 00 00 52 4C 41 41 }
		$f = { 5A 52 00 00 FF FF FF FF 0A 00 00 00 52 5C 4B 4D }
		$g = { 41 58 4B 5C 57 52 00 00 FF FF FF FF 0E 00 00 00 }
		$h = { 52 2A 5C 4B 4D 57 4D 42 4B 20 4C 47 40 52 00 00 }
		$i = { FF FF FF FF 0A 00 00 00 52 5E 4B 5C 48 42 41 49 }
		$j = { 5D 52 00 00 FF FF FF FF 05 00 00 00 52 4B 48 47 }
		$k = { 52 00 00 00 FF FF FF FF 0C 00 00 00 52 4D 41 40 }
		$l = { 48 47 49 20 43 5D 47 52 00 00 00 00 FF FF FF FF }
		$m = { 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 3F 52 00 00 }
		$n = { FF FF FF FF 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 }
		$o = { 3C 52 00 00 FF FF FF FF 08 00 00 00 52 49 41 41 }
		$p = { 49 42 4B 52 00 00 00 00 FF FF FF FF 06 00 00 00 }
		$q = { 52 5A 4B 43 5E 52 00 00 FF FF FF FF 08 00 00 00 }
		$v = { 52 48 3A 4C 4D 70 3F 52 00 00 00 00 FF FF FF FF }
		$w = { 0A 00 00 00 52 4F 42 42 5B 5D 4B 70 3F 52 00 00 }
		$x = { FF FF FF FF 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 }
		$y = { 3F 52 00 00 FF FF FF FF 0A 00 00 00 52 5E 5C 41 }
		$z = { 49 5C 4F 70 3C 52 00 00 FF FF FF FF 09 00 00 00 }
		$aa = { 52 4F 5E 5E 4A 4F 5A 4F 52 00 00 00 FF FF FF FF }
		$ab = { 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 3D 52 00 00 }
		$ac = { FF FF FF FF 08 00 00 00 52 5E 5B 4C 42 47 4D 52 }
		
    condition:
        all of them
}