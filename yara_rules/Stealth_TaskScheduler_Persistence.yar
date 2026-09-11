rule Stealth_TaskScheduler_Persistence {
    meta:
        author = "Eduardo"
        description = "Detecta persistência silenciosa usando nomes de tarefas legítimas via schtasks ou manipulação de atalhos (Startup)"
        severity = "High"
        mitre_tactic = "Persistence (TA0003) - Scheduled Task/Job (T1053)"

    strings:
        // Estrutura do comando
        $sch = "schtasks /create /tn" ascii wide nocase
        $args = "/sc onlogon /delay" ascii wide nocase
        
        // Nomes usados para mascaramento (Evasão de Defesa)
        $mask1 = "MicrosoftEdgeUpdateTaskMachineUA" ascii wide
        $mask2 = "OneDriveStandaloneUpdater" ascii wide
        $mask3 = "GoogleUpdateTaskMachineUA" ascii wide
        $mask4 = "WindowsSecurityHealthService" ascii wide
        
        // Persistência via PowerShell no Startup
        $ps_shortcut = "$WScriptShell.CreateShortcut" ascii wide nocase

    condition:
        ($sch and $args and any of ($mask*)) or $ps_shortcut
}
