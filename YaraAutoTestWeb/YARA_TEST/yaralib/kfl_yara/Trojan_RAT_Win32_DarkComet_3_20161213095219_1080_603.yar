rule Trojan_RAT_Win32_DarkComet_3_20161213095219_1080_603 
{
	meta:
		judge = "black"
		threatname = "Trojan[RAT]/Win32.DarkComet.5"
		threattype = "rat"
		family = "DarkComet"
		hacker = "None"
		refer = "430a4c9547582546ea238be55af72236,4fcd5e3d6b619ad574b414951c95a694,8B2014764027634969837C4EFE47FC88"
		description = "DarkComet RAT"
		comment = "None"
		author = "botherder https://github.com/botherder"
		date = "2016-11-22"
	strings:
		$bot1 = /(#)BOT#OpenUrl/ wide ascii
		$bot2 = /(#)BOT#Ping/ wide ascii
		$bot3 = /(#)BOT#RunPrompt/ wide ascii
		$bot4 = /(#)BOT#SvrUninstall/ wide ascii
		$bot5 = /(#)BOT#URLDownload/ wide ascii
		$bot6 = /(#)BOT#URLUpdate/ wide ascii
		$bot7 = /(#)BOT#VisitUrl/ wide ascii
		$bot8 = /(#)BOT#CloseServer/ wide ascii
		$ddos1 = /(D)DOSHTTPFLOOD/ wide ascii
		$ddos2 = /(D)DOSSYNFLOOD/ wide ascii
		$ddos3 = /(D)DOSUDPFLOOD/ wide ascii
		$keylogger1 = /(A)ctiveOnlineKeylogger/ wide ascii
		$keylogger2 = /(U)nActiveOnlineKeylogger/ wide ascii
		$keylogger3 = /(A)ctiveOfflineKeylogger/ wide ascii
		$keylogger4 = /(U)nActiveOfflineKeylogger/ wide ascii
		$shell1 = /(A)CTIVEREMOTESHELL/ wide ascii
		$shell2 = /(S)UBMREMOTESHELL/ wide ascii
		$shell3 = /(K)ILLREMOTESHELL/ wide ascii

	condition:
		4 of ($bot*) or all of ($ddos*) or all of ($keylogger*) or all of ($shell*)
}
