package com.cherepavel.vpndetector.detector

import java.util.Locale

object TunnelNameMatcher {

    private val tunnelPrefixes = listOf(
        "tun",
        "tap",
        "ppp",
        "wg",
        "utun",
        "ipsec",
        "xfrm",
        "zt",
        "tailscale"
    )

    private val tunnelContains = listOf(
        "vpn"
    )

    fun looksLikeTunnelName(name: String?): Boolean {
        val lowered = name?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (lowered.isBlank()) return false

        return tunnelPrefixes.any { lowered.startsWith(it) } ||
                tunnelContains.any { lowered.contains(it) }
    }
}
