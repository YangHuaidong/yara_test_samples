rule Trojan_Backdoor_Win32_Small_eyua_530_208
{ 

  meta: 
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Small.eyua"
        threattype = "Backdoor"
        family = "Small"
        hacker = "None"
        author = "@chort (@chort0)-mqx"
        refer = "f09d832bea93cf320986b53fce4b8397"
        comment = "None"
        date = "2018-07-26"
        description = "APT backdoor Pipcreat"

  strings: 
    $strA = "pip creat failed" wide fullword 
    $strB = "CraatePipe" ascii fullword 
    $strC = "are you there? " wide fullword 
    $strD = "success kill process ok" wide fullword 
    $strE = "Vista|08|Win7" wide fullword 
    $rut = "are you there!@#$%^&*()_+" ascii fullword 
    
  condition: 
    $rut or (2 of ($str*)) 
  }
