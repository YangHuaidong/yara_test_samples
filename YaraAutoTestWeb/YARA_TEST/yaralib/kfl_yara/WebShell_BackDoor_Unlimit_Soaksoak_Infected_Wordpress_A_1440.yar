rule WebShell_BackDoor_Unlimit_Soaksoak_Infected_Wordpress_A_1440 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/12/15"
    description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
    family = "Soaksoak"
    hacker = "None"
    judge = "unknown"
    reference = "http://goo.gl/1GzWUX"
    score = 60
    threatname = "WebShell[BackDoor]/Unlimit.Soaksoak.Infected.Wordpress.A"
    threattype = "BackDoor"
  strings:
    $s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
    $s1 = "function FuncQueueObject()" ascii fullword
    $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
  condition:
    all of ($s*)
}