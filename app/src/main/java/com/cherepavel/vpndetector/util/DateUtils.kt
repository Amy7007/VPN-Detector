package com.cherepavel.vpndetector.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private const val DEFAULT_DATE_PATTERN = "yyyy-MM-dd HH:mm:ss"

fun nowString(pattern: String = DEFAULT_DATE_PATTERN): String {
    return SimpleDateFormat(pattern, Locale.US).format(Date())
}
