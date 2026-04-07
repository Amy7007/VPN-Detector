package com.cherepavel.vpndetector.detector

data class IfconfigInterfaceInfo(
    val name: String?,
    val flags: String?,
    val address: String?,
    val netmask: String?,
    val broadcast: String?,
    val isUp: Boolean
) {
    fun normalizedName(): String = name?.trim().orEmpty()

    fun hasUsableAddress(): Boolean {
        val value = address?.trim().orEmpty()
        return value.isNotEmpty() && value != "-" && value != "null"
    }

    fun isLoopbackLike(): Boolean {
        val lowered = normalizedName().lowercase()
        return lowered == "lo" || lowered.startsWith("lo")
    }

    fun isPointToPointLike(): Boolean {
        val loweredFlags = flags?.lowercase().orEmpty()
        return loweredFlags.contains("pointopoint") ||
                loweredFlags.contains("point-to-point")
    }

    fun looksLikeTunnel(): Boolean {
        val normalized = normalizedName()
        return TunnelNameMatcher.looksLikeTunnelName(normalized) ||
                (!isLoopbackLike() && hasUsableAddress() && isPointToPointLike())
    }

    fun toDisplayBlock(): String {
        val displayName = normalizedName().ifBlank { "unknown" }
        val displayFlags = flags?.takeIf { it.isNotBlank() } ?: ""
        val displayAddress = address ?: "-"
        val displayNetmask = netmask ?: "-"
        val displayBroadcast = broadcast ?: "-"
        val upDown = if (isUp) "UP" else "DOWN"

        return buildString {
            append(displayName)
            append("  ")
            append(upDown)

            if (displayFlags.isNotBlank()) {
                append("  flags=")
                append(displayFlags)
            }

            append("\n")
            append("  addr=")
            append(displayAddress)
            append("\n")
            append("  mask=")
            append(displayNetmask)
            append("\n")
            append("  broadcast=")
            append(displayBroadcast)
        }
    }
}
