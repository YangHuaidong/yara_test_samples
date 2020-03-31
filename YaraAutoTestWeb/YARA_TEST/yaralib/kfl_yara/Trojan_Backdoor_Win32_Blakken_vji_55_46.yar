rule Trojan_Backdoor_Win32_Blakken_vji_55_46 
{

    meta:	
        judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Blakken.vji"
		threattype = "Backdoor"
		family = "Blakken"
		hacker = "None"
		comment = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
		date = "2016-01-04"
		author = "Florian Roth--DC"
		description = "Auto-generated rule - from files 7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094, b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a, edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281" 
		refer = "1e439a13df4b7603f5eb7a975235065e"
		super_rule = 1
        hash1 = "1e439a13df4b7603f5eb7a975235065e"
        hash2 = "03e9477f8da8f6f61b03a01d5a38918f"
        hash3 = "ed55997aada076dc61e20e1d1218925a"
        hash4 = "60d3185aff17084297a2c4c2efdabdc9"
        hash5 = "a0b7b80c3c1d9c1c432a740fa17c6126"
        hash6 = "97d6d1b36171bc3eafdd0dc07e7a4d2d"
        hash7 = "e60854c96fab23f2c857dd6eb745961c"
        hash8 = "2cae5e949f1208d13150a9d492a706c1"
    
    strings:
        $s1 = "USB MDM Driver" fullword wide
        $s2 = "KdDebuggerNotPresent" fullword ascii /* Goodware String - occured 50 times */
        $s3 = "KdDebuggerEnabled" fullword ascii /* Goodware String - occured 69 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 180KB and all of them
}