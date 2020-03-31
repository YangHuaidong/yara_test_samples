rule Trojan_Backdoor_Win32_Regin_aaaaai_506_188
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Regin.aaaaai"
        threattype = "Backdoor"
        family = "Regin"
        hacker = "None"
        author = "balala"
        refer = "85bd9de0382a13c09705c26a8306e22e,02c5c3983983d15405875894cab47bac"
		comment = "None"
        date = "2018-08-02"
        description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
    

    strings:
        $s0 = "HAL.dll" fullword ascii
        $s1 = "IoGetDeviceObjectPointer" fullword ascii
        $s2 = "MaximumPortsServiced" fullword wide
        $s3 = "KeGetCurrentIrql" fullword ascii
        $s4 = "ntkrnlpa.exe" fullword ascii
        $s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
        $s6 = "ConnectMultiplePorts" fullword wide
        $s7 = "\\SYSTEMROOT" fullword wide
        $s8 = "IoWriteErrorLogEntry" fullword ascii
        $s9 = "KeQueryPerformanceCounter" fullword ascii
        $s10 = "KeServiceDescriptorTable" fullword ascii
        $s11 = "KeRemoveEntryDeviceQueue" fullword ascii
        $s12 = "SeSinglePrivilegeCheck" fullword ascii
        $s13 = "KeInitializeEvent" fullword ascii
        $s14 = "IoBuildDeviceIoControlRequest" fullword ascii
        $s15 = "KeRemoveDeviceQueue" fullword ascii
        $s16 = "IofCompleteRequest" fullword ascii
        $s17 = "KeInitializeSpinLock" fullword ascii
        $s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
        $s19 = "IoCreateDevice" fullword ascii
        $s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
   
    condition:
        all of them and filesize < 40KB and filesize > 30KB
}