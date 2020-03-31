rule Trojan_Win32_Chicken_mm_5_20161213095306_1113_653 
{
	meta:
		judge = "black"
		threatname = "Trojan/Win32.Chicken_mm.5"
		threattype = "DDOS"
		family = "Chicken_mm"
		hacker = "none"
		refer = "d5ae6a10a7dd6ab60b80287d210a62d0,CA692B09A0F11531F0CA0A04C677572B"
		description = "None"
		comment = "None"
		author = "dongjianwu"
		date = "2016-09-01"
	strings:
		$s0 = "fake.cfg"
		$s1 = "CThreadNormalAtkExcutor"
		$s2 = "FakeUserAtk"
		$s3 = "CThreadAttack"

	condition:
		3 of them
}
