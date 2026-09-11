rule LSASS_Impersonation_DPAPI_Stealer {
    meta:
        author = "Eduardo"
        description = "Detecta roubo de credenciais via impersonation do LSASS (ctypes) e manipulação do provedor NCrypt (v10/v20/App-Bound)"
        severity = "Critical"
        mitre_tactic = "Credential Access (TA0006) - OS Credential Dumping (T1003)"

    strings:
        // APIs críticas do Windows para escalação/roubo de token
        $api1 = "SeDebugPrivilege" ascii wide
        $api2 = "ImpersonateLoggedOnUser" ascii wide
        $api3 = "DuplicateTokenEx" ascii wide
        $api4 = "NCryptOpenStorageProvider" ascii wide
        
        // Assinaturas lógicas do artefato Python
        $python_lsass = "impersonate_lsass_ctypes" ascii wide
        $browser_crypt1 = "app_bound_encrypted_key" ascii wide
        $browser_crypt2 = "PK11SDR_Decrypt" ascii wide // Decrypt da nss3.dll (Firefox)

    condition:
        ($python_lsass) or (3 of ($api*)) or ($browser_crypt1 and $browser_crypt2)
}
