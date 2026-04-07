package com.cherepavel.vpndetector.util

import android.net.NetworkCapabilities
import android.os.Build

object TransportInfoFormatter {

    fun summarizeVpnTransportInfo(capabilities: NetworkCapabilities?): String? {
        if (capabilities == null) return null
        if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null

        val transportInfo = capabilities.transportInfo ?: return null
        val text = transportInfo.javaClass.simpleName ?: transportInfo.toString()

        return text
            .takeIf { it.isNotBlank() }
            .takeIf { !it.equals("WifiInfo", ignoreCase = true) }
            .takeIf {
                !it.equals("VcnTransportInfo", ignoreCase = true) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
    }
}
