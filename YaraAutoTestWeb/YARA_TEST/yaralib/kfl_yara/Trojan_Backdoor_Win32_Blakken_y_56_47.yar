rule Trojan_Backdoor_Win32_Blakken_y_56_47 
{

    meta:
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Blakken.y"
		threattype = "Backdoor"
		family = "Blakken"
		hacker = "None"
		comment = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
		date = "2016-01-04"
		author = "Florian Roth--DC"
		description = "Auto-generated rule - from files 32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614, 3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2, 90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c, 97be6b2cec90f655ef11ed9feef5b9ef057fd8db7dd11712ddb3702ed7c7bda1" 
		refer = "18e7885eab07ebfb6d1c9303b992ca21"
		super_rule = 1
		hash1 = "18e7885eab07ebfb6d1c9303b992ca21"
        hash2 = "97b41d4b8d05a1e165ac4cc2a8ac6f39"
        hash3 = "c2fb8a309aef65e46323d6710ccdd6ca"
        hash4 = "956246139f93a83f134a39cd55512f6d"
        hash5 = "979413f9916e8462e960a4eb794824fc"
        hash6 = "0037b485aa6938ba2ead234e211425bb"
        hash7 = "d98f4fc6d8bb506b27d37b89f7ce89d0"
   
    strings:
        $s1 = " AMD IDE driver" fullword wide
        $s2 = "SessionEnv" fullword wide
        $s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
        $s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
    
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}
