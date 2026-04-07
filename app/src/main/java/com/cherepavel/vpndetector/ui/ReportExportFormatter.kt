package com.cherepavel.vpndetector.ui

import com.cherepavel.vpndetector.util.nowString

object ReportExportFormatter {

    data class ExportInput(
        val report: DetectionReport,
        val nativeDetailsRaw: String,
        val javaTunnelNames: List<String>,
        val installedVpnApps: List<String>
    )

    fun buildText(input: ExportInput): String {
        val report = input.report

        return buildString {
            appendLine("VPN Detector Report")
            appendLine("Generated: ${nowString()}")
            appendLine()

            appendLine("=== OVERALL STATUS ===")
            appendLine(report.overallTitle)
            appendLine(report.overallSummary)
            appendLine(report.overallExplanation)
            appendLine()

            appendLine("=== OFFICIAL ANDROID API ===")
            appendLine("TRANSPORT_VPN across all networks: ${report.transportAnyValue}")
            appendLine("TRANSPORT_VPN active network only: ${report.transportActiveValue}")
            appendLine("Transport state: ${report.transportStateText}")
            appendLine("Transport subtitle: ${report.transportSubtitle}")
            appendLine()

            if (report.apiSignals.isNotEmpty()) {
                appendLine("API signals:")
                report.apiSignals.forEach { signal ->
                    appendLine("- ${signal.title}")
                    appendLine("  source: ${signal.source}")
                    appendLine("  value: ${signal.value}")
                    appendLine("  hint: ${signal.hint}")
                }
                appendLine()
            }

            appendLine("=== NATIVE LOW-LEVEL ENUMERATION ===")
            appendLine("Signal value: ${report.nativeSignal.value}")
            appendLine("Signal hint: ${report.nativeSignal.hint}")
            appendLine()
            appendLine(input.nativeDetailsRaw)
            appendLine()

            appendLine("=== JAVA INTERFACE ENUMERATION ===")
            appendLine("Signal value: ${report.javaSignal.value}")
            appendLine("Signal hint: ${report.javaSignal.hint}")
            if (input.javaTunnelNames.isNotEmpty()) {
                appendLine("Matched tunnel-like names:")
                input.javaTunnelNames.forEach { appendLine("- $it") }
            }
            appendLine()

            appendLine("=== DETECTED VPN APPS ===")
            if (input.installedVpnApps.isEmpty()) {
                appendLine("No known VPN-related apps from the tracked list are installed.")
            } else {
                input.installedVpnApps.forEach { appendLine("- $it") }
            }
        }.trim()
    }
}
