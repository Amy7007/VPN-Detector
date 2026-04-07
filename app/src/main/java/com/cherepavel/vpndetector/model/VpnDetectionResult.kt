package com.cherepavel.vpndetector.model

data class VpnDetectionResult(
    val activeNetworkPresent: Boolean,
    val activeNetworkIsVpn: Boolean?,
    val anyNetworkHasVpnTransport: Boolean,
    val activeNetworkHasInternet: Boolean,
    val vpnNetworks: List<VpnNetworkInfo>
)
