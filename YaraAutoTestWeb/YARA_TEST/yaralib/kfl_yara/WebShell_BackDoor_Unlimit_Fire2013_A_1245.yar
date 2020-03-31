rule WebShell_BackDoor_Unlimit_Fire2013_A_1245 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/07/18"
    description = "Catches a webshell"
    family = "Fire2013"
    hacker = "None"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Fire2013.A"
    threattype = "BackDoor"
  strings:
    $a = "eval(\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61"
    $b = "yc0CJYb+O//Xgj9/y+U/dd//vkf'\\x29\\x29\\x29\\x3B\")"
  condition:
    all of them
}