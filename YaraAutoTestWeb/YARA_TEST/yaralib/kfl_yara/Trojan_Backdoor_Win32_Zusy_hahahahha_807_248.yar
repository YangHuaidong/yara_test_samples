rule Trojan_Backdoor_Win32_Zusy_hahahahha_807_248
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Zusy.hahahahha"
        threattype = "Backdoor"
        family = "Zusy"
        hacker = "None"
        author = "balala"
        refer = "a42cea20439789bd1d9a51d9063ae3e4,8bd58db9c29c53197dd5d5f09704296e,14f2e86f11114c083856c92095d79256,4215d029dd26c29ce3e0cab530979b19"
        comment = "None"
        date = "2018-10-22"
        description = "None"
	strings:
        $s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
   
    condition:
        all of them
}