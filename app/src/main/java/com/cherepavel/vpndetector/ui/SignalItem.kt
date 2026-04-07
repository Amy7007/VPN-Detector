package com.cherepavel.vpndetector.ui

data class SignalItem(
    val title: String,
    val source: String,
    val value: String,
    val state: SignalState,
    val hint: String
)

enum class SignalState {
    POSITIVE, // red = VPN signal present
    NEGATIVE, // green = no signal
    WARNING,  // orange = heuristic / indirect signal
    NEUTRAL,  // gray = informational
    SEMI      // blue = split / partial / ambiguous
}
