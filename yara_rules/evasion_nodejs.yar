rule NodeJS_Advanced_Evasion_Techniques {
    meta:
        author = "Eduardo"
        description = "Detecta técnicas agressivas de Anti-VM e Anti-Debugging usadas em scripts NodeJS/V8"
        severity = "High"

    strings:
        // Comandos de enumeração de hardware via WMI
        $wmi1 = "wmic cpu get name /value" ascii wide nocase
        $wmi2 = "wmic path win32_VideoController get name /value" ascii wide nocase
        $wmi3 = "wmic computersystem get model /value" ascii wide nocase
        
        // Placas de vídeo irreais (Sinal de Sandbox/VM)
        $gpu1 = "vmware svga" ascii wide nocase
        $gpu2 = "virtualbox graphics adapter" ascii wide nocase
        
        // Processos de análise (Blacklist)
        $proc1 = "wireshark.exe" ascii wide nocase
        $proc2 = "x64dbg.exe" ascii wide nocase
        $proc3 = "joeboxcontrol" ascii wide nocase
        
        // Identificadores de ambiente NodeJS
        $node1 = "evalmachine.<anonymous>" ascii wide
        $node2 = "child_process" ascii wide

    condition:
        all of ($node*) and (any of ($wmi*) or any of ($gpu*) or 2 of ($proc*))
}
