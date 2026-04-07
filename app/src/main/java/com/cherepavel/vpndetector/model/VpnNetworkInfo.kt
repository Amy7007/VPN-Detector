package com.cherepavel.vpndetector.model

data class VpnNetworkInfo(
    val interfaceName: String?,
    val transports: List<String>,
    val capabilities: List<String>,
    val transportInfoSummary: String?
)
