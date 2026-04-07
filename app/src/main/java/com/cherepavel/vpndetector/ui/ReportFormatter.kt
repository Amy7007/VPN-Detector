package com.cherepavel.vpndetector.ui

import com.cherepavel.vpndetector.detector.TunnelNameMatcher

data class DetectionReport(
    val overallTitle: String,
    val overallSummary: String,
    val overallExplanation: String,
    val overallState: SignalState,

    val transportCardState: SignalState,
    val transportStateText: String,
    val transportSubtitle: String,
    val transportAnyValue: String,
    val transportActiveValue: String,

    val apiSignals: List<SignalItem>,
    val nativeSignal: SignalItem,
    val nativeDetails: String,
    val javaSignal: SignalItem,
    val knownAppsText: String
)

object ReportFormatter {

    data class RawInput(
        val hasTransportVpnAny: Boolean,
        val hasTransportVpnActive: Boolean,
        val interfaceName: String?,
        val transportInfoSummary: String?,
        val nativeTunnelNames: List<String>,
        val nativeDetails: List<String>,
        val javaTunnelNames: List<String>,
        val installedVpnApps: List<String>
    )

    fun build(input: RawInput): DetectionReport {
        val anyVpn = input.hasTransportVpnAny
        val activeVpn = input.hasTransportVpnActive

        val interfaceDetected = TunnelNameMatcher.looksLikeTunnelName(input.interfaceName)
        val transportInfoDetected = !input.transportInfoSummary.isNullOrBlank()
        val nativeDetected = input.nativeTunnelNames.isNotEmpty()
        val javaDetected = input.javaTunnelNames.isNotEmpty()
        val appsDetected = input.installedVpnApps.isNotEmpty()

        val overall = buildOverallBlock(
            activeVpn = activeVpn,
            anyVpn = anyVpn,
            interfaceDetected = interfaceDetected,
            transportInfoDetected = transportInfoDetected,
            nativeDetected = nativeDetected,
            javaDetected = javaDetected,
            appsDetected = appsDetected
        )

        val apiSignals = buildApiSignals(
            interfaceName = input.interfaceName,
            interfaceDetected = interfaceDetected,
            transportInfoSummary = input.transportInfoSummary,
            transportInfoDetected = transportInfoDetected,
            activeVpn = activeVpn,
            anyVpn = anyVpn
        )

        val nativeSignal = SignalItem(
            title = "Tunnel-like interfaces",
            source = "Native getifaddrs() enumeration",
            value = input.nativeTunnelNames.ifEmpty { listOf("none") }.joinToString(", "),
            state = if (nativeDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (nativeDetected) {
                "Native enumeration found interfaces whose names or properties look tunnel-like."
            } else {
                "Native enumeration did not find any tunnel-like interfaces."
            }
        )

        val javaSignal = SignalItem(
            title = "Tunnel-like interfaces",
            source = "Java NetworkInterface enumeration",
            value = input.javaTunnelNames.ifEmpty { listOf("none") }.joinToString(", "),
            state = if (javaDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (javaDetected) {
                "Java network enumeration found interface names that look like VPN or tunnel interfaces."
            } else {
                "Java network enumeration did not find any tunnel-like interface names."
            }
        )

        val nativeDetailsText = if (input.nativeDetails.isEmpty()) {
            "No interfaces were returned by the native detector."
        } else {
            input.nativeDetails.joinToString(separator = "\n\n")
        }

        val appsText = if (input.installedVpnApps.isEmpty()) {
            "No known VPN-related apps from the tracked list are installed."
        } else {
            input.installedVpnApps.joinToString(separator = "\n") { "• $it" }
        }

        return DetectionReport(
            overallTitle = overall.title,
            overallSummary = overall.summary,
            overallExplanation = overall.explanation,
            overallState = overall.state,

            transportCardState = overall.transportState,
            transportStateText = overall.transportText,
            transportSubtitle = overall.transportSubtitle,
            transportAnyValue = if (anyVpn) "DETECTED" else "NOT DETECTED",
            transportActiveValue = if (activeVpn) "DETECTED" else "NOT DETECTED",

            apiSignals = apiSignals,
            nativeSignal = nativeSignal,
            nativeDetails = nativeDetailsText,
            javaSignal = javaSignal,
            knownAppsText = appsText
        )
    }

    private fun buildOverallBlock(
        activeVpn: Boolean,
        anyVpn: Boolean,
        interfaceDetected: Boolean,
        transportInfoDetected: Boolean,
        nativeDetected: Boolean,
        javaDetected: Boolean,
        appsDetected: Boolean
    ): OverallBlock {
        return when {
            activeVpn -> {
                OverallBlock(
                    title = "VPN detected",
                    summary = "The active network is explicitly marked as VPN by Android.",
                    explanation = "This is the strongest signal in the app: Android reports TRANSPORT_VPN on the network currently in use.",
                    state = SignalState.POSITIVE,
                    transportState = SignalState.POSITIVE,
                    transportText = "VPN DETECTED",
                    transportSubtitle = "TRANSPORT_VPN is present on the active network."
                )
            }

            anyVpn -> {
                OverallBlock(
                    title = "VPN present outside active path",
                    summary = "Android sees a VPN network in the system, but not on the current active network.",
                    explanation = "This often matches bypass or split-tunnel behavior: a VPN exists, but current traffic may not be fully routed through it.",
                    state = SignalState.SEMI,
                    transportState = SignalState.SEMI,
                    transportText = "SPLIT / BYPASS",
                    transportSubtitle = "A VPN-related transport exists system-wide, but it is not the current active path."
                )
            }

            interfaceDetected || transportInfoDetected -> {
                OverallBlock(
                    title = "VPN-related API signal",
                    summary = "Android APIs still expose VPN-like indicators even though active TRANSPORT_VPN is absent.",
                    explanation = "This is weaker than a direct VPN transport flag, but it still suggests that VPN-related state may be visible through official APIs.",
                    state = SignalState.WARNING,
                    transportState = SignalState.WARNING,
                    transportText = "API SIGNAL",
                    transportSubtitle = "No active TRANSPORT_VPN, but Android APIs still expose VPN-related information."
                )
            }

            nativeDetected || javaDetected -> {
                OverallBlock(
                    title = "Low-level tunnel signal",
                    summary = "No primary Android VPN signal was found, but tunnel-like interfaces were still discovered.",
                    explanation = "This usually means only low-level interface heuristics fired. It is useful as an additional hint, but weaker than official Android VPN signals.",
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            appsDetected -> {
                OverallBlock(
                    title = "Detected VPN apps",
                    summary = "No active VPN network signal was found, but known VPN-related apps are installed on the device.",
                    explanation = "Installed VPN apps do not prove that a VPN is currently active, but they are still a relevant contextual signal.",
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            else -> {
                OverallBlock(
                    title = "No VPN detected",
                    summary = "The app did not find any high-level or low-level VPN indicators.",
                    explanation = "Neither official Android network APIs nor interface enumeration produced a VPN-related signal.",
                    state = SignalState.NEGATIVE,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "No VPN transport was reported by Android."
                )
            }
        }
    }

    private fun buildApiSignals(
        interfaceName: String?,
        interfaceDetected: Boolean,
        transportInfoSummary: String?,
        transportInfoDetected: Boolean,
        activeVpn: Boolean,
        anyVpn: Boolean
    ): List<SignalItem> {
        val interfaceState = when {
            interfaceDetected && (activeVpn || anyVpn) -> SignalState.POSITIVE
            interfaceDetected -> SignalState.WARNING
            else -> SignalState.NEGATIVE
        }

        val transportInfoState = when {
            transportInfoDetected && (activeVpn || anyVpn) -> SignalState.POSITIVE
            transportInfoDetected -> SignalState.WARNING
            else -> SignalState.NEGATIVE
        }

        val interfaceHint = when {
            interfaceDetected && activeVpn ->
                "The interface name itself looks like a tunnel device and matches the active VPN state."
            interfaceDetected && anyVpn ->
                "The interface name looks tunnel-like and is consistent with a VPN being present somewhere in the system."
            interfaceDetected ->
                "The interface name looks tunnel-like, but Android does not currently mark the active path as VPN."
            else ->
                "The interface name does not look like a typical VPN or tunnel interface."
        }

        val transportInfoHint = when {
            transportInfoDetected && activeVpn ->
                "Android returned transport info alongside an active VPN transport."
            transportInfoDetected && anyVpn ->
                "Transport info is present and aligns with a VPN existing somewhere in the network stack."
            transportInfoDetected ->
                "Transport info is present, but without a direct active VPN transport flag."
            else ->
                "No VPN-related transport info was exposed here."
        }

        return listOf(
            SignalItem(
                title = "Interface name",
                source = "LinkProperties.getInterfaceName()",
                value = interfaceName ?: "none",
                state = interfaceState,
                hint = interfaceHint
            ),
            SignalItem(
                title = "Transport info",
                source = "NetworkCapabilities.getTransportInfo()",
                value = transportInfoSummary ?: "none",
                state = transportInfoState,
                hint = transportInfoHint
            )
        )
    }

    private data class OverallBlock(
        val title: String,
        val summary: String,
        val explanation: String,
        val state: SignalState,
        val transportState: SignalState,
        val transportText: String,
        val transportSubtitle: String
    )
}
