rule Credential_Access_Crypto_And_Injectors {
    meta:
        author = "Eduardo"
        description = "Detecta manipulação do core do Discord (injeção) e extração de seeds de carteiras Exodus/Extensões"
        severity = "Critical"

    strings:
        // Injeção no cliente do Discord
        $inj1 = "discord_desktop_core" ascii wide nocase
        $inj2 = "module.exports = require('./core.asar')" ascii wide nocase
        $inj3 = "betterdiscord.asar" ascii wide nocase
        $inj4 = "InstallDiscordInject" ascii wide nocase
        
        // Roubo da carteira Exodus e quebra de criptografia (SECO)
        $exo1 = "EXODUS_PASSWORD_TEMP_FILE" ascii wide
        $exo2 = "tryDecryptExodusSeedLegacy" ascii wide
        $exo3 = "extractSecoPayload" ascii wide
        
        // Roubo de Backup Codes (2FA)
        $bkp1 = "github-recovery-codes.txt" ascii wide
        $bkp2 = "Epic Games Account Two-Factor" ascii wide nocase
        $bkp3 = "discord_backup_codes.txt" ascii wide nocase

    condition:
        2 of ($inj*) or 2 of ($exo*) or 2 of ($bkp*)
}
