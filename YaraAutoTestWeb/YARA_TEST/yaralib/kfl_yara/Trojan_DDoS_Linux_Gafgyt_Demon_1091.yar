rule Trojan_DDoS_Linux_Gafgyt_Demon_1091
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Demon"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "0f57b601e33da3ab587bc038f51fe894,0bf4440284f6f0ac26246d82b242f9d7,fe424b036d0cfaac97421908fd99119c,17338c5dde88c653e2fd00323401b039,7e6b103e41c2ab4d383eace24176c7df"
		author = "Luoxuan"
		comment = "None"
		date = "2019-04-10"
		description = "None"

	strings:
		$s0 = "w70uUC1UJYZoPENznHXB"
		$s1 = "L33T HaxErS"
		$s2 = "[1;31mDemon\x1B[1;37m[\x1B[1;31mV5"
		$s3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We"
		//$s4 = "\x1B[0;36m%s\x1B[1;37m]\x1B[1;31m-->\x1B[1;37m[\x1B[0;36m%s\x1B"
		//$s5 = "[1;37m]\x1B[1;31m-->\x1B[1;37m[\x1B[0;36m%s\x1B[1;37m]"
		//$s6 = "JezacHw4VfzRWzsglZlF"
		//$s7 = "linuxshell || system || enable || sh || shell || bah"
		//$s8 = "sending wget payload"
	condition:
		all of them
}