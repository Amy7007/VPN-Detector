package com.cherepavel.vpndetector.detector

object IfconfigTermuxLikeDetector {

    init {
        try {
            System.loadLibrary("ifconfigdetector")
        } catch (_: Throwable) {
        }
    }

    external fun getInterfacesNative(): Array<String>

    fun detect(): IfconfigTermuxLikeResult {
        val allBlocks = try {
            getInterfacesNative().toList()
        } catch (_: Throwable) {
            emptyList()
        }

        val matched = allBlocks.filter { block ->
            val firstLine = block.lineSequence().firstOrNull().orEmpty()
            TunnelNameMatcher.looksLikeTunnelName(firstLine.substringBefore(':').trim())
        }

        return IfconfigTermuxLikeResult(
            vpnLikely = matched.isNotEmpty(),
            matchedInterfaces = matched,
            allInterfaces = allBlocks
        )
    }
}
