#!/usr/bin/env kotlin

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Base64

data class RouteSpec(
    val name: String,
    val domainFileName: String,
    val ipFileName: String,
    val siteKey: String,
    val ipKey: String,
    val minimumRuleCount: Int
)

val routingUrl =
    "https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/main/HAPP/DEFAULT.JSON"

val httpClient =
    HttpClient
        .newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

val downloadCache = mutableMapOf<String, String>()
val binaryDownloadCache = mutableMapOf<String, ByteArray>()

fun download(url: String): String {
    downloadCache[url]?.let { return it }
    var lastFailure = "неизвестная ошибка"

    repeat(4) { attempt ->
        val request =
            HttpRequest
                .newBuilder(URI.create(url))
                .header("User-Agent", "shadowrocket-roscomvpn-routing")
                .timeout(Duration.ofSeconds(60))
                .GET()
                .build()
        try {
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() in 200..299) {
                val body = response.body()
                check(body.isNotBlank()) { "Источник $url вернул пустой ответ" }
                check(body.length <= 20_000_000) { "Источник $url превышает лимит 20 МБ" }
                downloadCache[url] = body
                return body
            }

            lastFailure = "HTTP ${response.statusCode()}"
            check(response.statusCode() == 429 || response.statusCode() in 500..599) {
                "Не удалось скачать $url: $lastFailure"
            }
        } catch (error: IOException) {
            lastFailure = error.message ?: error.javaClass.simpleName
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw error
        }

        if (attempt < 3) {
            Thread.sleep(2_000L shl attempt)
        }
    }

    error("Не удалось скачать $url после 4 попыток: $lastFailure")
}

fun downloadBytes(url: String): ByteArray {
    binaryDownloadCache[url]?.let { return it }
    var lastFailure = "неизвестная ошибка"
    repeat(4) { attempt ->
        val request =
            HttpRequest
                .newBuilder(URI.create(url))
                .header("User-Agent", "shadowrocket-roscomvpn-routing")
                .timeout(Duration.ofSeconds(60))
                .GET()
                .build()
        try {
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray())
            if (response.statusCode() in 200..299) {
                val body = response.body()
                check(body.isNotEmpty() && body.size <= 20_000_000) { "Некорректный размер $url: ${body.size}" }
                binaryDownloadCache[url] = body
                return body
            }

            lastFailure = "HTTP ${response.statusCode()}"
            check(response.statusCode() == 429 || response.statusCode() in 500..599) {
                "Не удалось скачать $url: $lastFailure"
            }
        } catch (error: IOException) {
            lastFailure = error.message ?: error.javaClass.simpleName
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw error
        }

        if (attempt < 3) {
            Thread.sleep(2_000L shl attempt)
        }
    }
    error("Не удалось скачать $url после 4 попыток: $lastFailure")
}

sealed interface JsonValue

data class JsonStringValue(val value: String) : JsonValue

data class JsonArrayValue(val values: List<JsonValue>) : JsonValue

data class JsonObjectValue(val values: Map<String, JsonValue>) : JsonValue

data class JsonLiteralValue(val value: String) : JsonValue

class StrictJsonParser(private val source: String) {
    private var index = 0

    fun parseDocument(): JsonObjectValue {
        val value = parseValue()
        skipWhitespace()
        check(index == source.length) {
            "После JSON обнаружены лишние данные в позиции $index"
        }
        return value as? JsonObjectValue
            ?: error("Корневое значение DEFAULT.JSON должно быть объектом")
    }

    private fun parseValue(): JsonValue {
        skipWhitespace()
        check(index < source.length) { "Неожиданный конец JSON" }
        return when (source[index]) {
            '"' -> JsonStringValue(parseString())
            '[' -> parseArray()
            '{' -> parseObject()
            else -> parseLiteral()
        }
    }

    private fun parseObject(): JsonObjectValue {
        expect('{')
        skipWhitespace()
        val values = linkedMapOf<String, JsonValue>()
        if (consume('}')) {
            return JsonObjectValue(values)
        }
        while (true) {
            check(index < source.length && source[index] == '"') {
                "В JSON-объекте ожидался строковый ключ в позиции $index"
            }
            val key = parseString()
            skipWhitespace()
            expect(':')
            val value = parseValue()
            check(values.put(key, value) == null) { "В JSON повторяется ключ $key" }
            skipWhitespace()
            if (consume('}')) {
                return JsonObjectValue(values)
            }
            expect(',')
            skipWhitespace()
            check(index < source.length && source[index] != '}') {
                "В JSON-объекте обнаружена завершающая запятая"
            }
        }
    }

    private fun parseArray(): JsonArrayValue {
        expect('[')
        skipWhitespace()
        val values = mutableListOf<JsonValue>()
        if (consume(']')) {
            return JsonArrayValue(values)
        }
        while (true) {
            values.add(parseValue())
            skipWhitespace()
            if (consume(']')) {
                return JsonArrayValue(values)
            }
            expect(',')
            skipWhitespace()
            check(index < source.length && source[index] != ']') {
                "В JSON-массиве обнаружена завершающая запятая"
            }
        }
    }

    private fun parseString(): String {
        expect('"')
        return buildString {
            while (index < source.length) {
                val character = source[index++]
                when {
                    character == '"' -> return@buildString
                    character == '\\' -> appendEscapedCharacter()
                    character.code < 0x20 -> error("Управляющий символ в JSON-строке")
                    else -> append(character)
                }
            }
            error("JSON-строка не закрыта")
        }
    }

    private fun StringBuilder.appendEscapedCharacter() {
        check(index < source.length) { "JSON escape-последовательность не завершена" }
        when (val escaped = source[index++]) {
            '"' -> append('"')
            '\\' -> append('\\')
            '/' -> append('/')
            'b' -> append('\b')
            'f' -> append('\u000C')
            'n' -> append('\n')
            'r' -> append('\r')
            't' -> append('\t')
            'u' -> append(parseUnicodeEscape())
            else -> error("Некорректная JSON escape-последовательность: \\$escaped")
        }
    }

    private fun parseUnicodeEscape(): Char {
        check(index + 4 <= source.length) {
            "Unicode escape-последовательность не завершена"
        }
        val hexadecimal = source.substring(index, index + 4)
        check(hexadecimal.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            "Некорректная Unicode escape-последовательность: $hexadecimal"
        }
        index += 4
        return hexadecimal.toInt(16).toChar()
    }

    private fun parseLiteral(): JsonLiteralValue {
        val start = index
        while (index < source.length && source[index] !in setOf(',', ']', '}', ' ', '\t', '\r', '\n')) {
            index++
        }
        val literal = source.substring(start, index)
        val numberPattern = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")
        check(literal in setOf("true", "false", "null") || numberPattern.matches(literal)) {
            "Некорректный JSON literal в позиции $start: $literal"
        }
        return JsonLiteralValue(literal)
    }

    private fun skipWhitespace() {
        while (index < source.length && source[index] in setOf(' ', '\t', '\r', '\n')) {
            index++
        }
    }

    private fun consume(expected: Char): Boolean {
        if (index >= source.length || source[index] != expected) {
            return false
        }
        index++
        return true
    }

    private fun expect(expected: Char) {
        check(consume(expected)) { "В позиции $index ожидался символ $expected" }
    }
}

fun jsonString(json: JsonObjectValue, key: String): String {
    val value = json.values[key] ?: error("В DEFAULT.JSON отсутствует поле $key")
    return (value as? JsonStringValue)?.value ?: error("Поле $key должно быть строкой")
}

fun jsonArray(json: JsonObjectValue, key: String): List<String> {
    val array = json.values[key] as? JsonArrayValue ?: error("Поле $key должно быть массивом")
    return array.values.mapIndexed { index, value ->
        (value as? JsonStringValue)?.value
            ?: error("Элемент $index массива $key должен быть строкой")
    }
}

fun jsonStringMap(json: JsonObjectValue, key: String): Map<String, String> {
    val objectValue =
        json.values[key] as? JsonObjectValue
            ?: error("Поле $key должно быть объектом")
    return objectValue.values.mapValues { (nestedKey, value) ->
        (value as? JsonStringValue)?.value
            ?: error("Значение $nestedKey объекта $key должно быть строкой")
    }
}

fun jsonQuote(value: String): String =
    buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append("\\u${character.code.toString(16).padStart(4, '0')}")
                } else {
                    append(character)
                }
            }
        }
        append('"')
    }

fun renderJson(value: JsonValue, depth: Int = 0): String =
    when (value) {
        is JsonStringValue -> jsonQuote(value.value)
        is JsonLiteralValue -> value.value
        is JsonArrayValue -> {
            if (value.values.isEmpty()) {
                "[]"
            } else {
                value.values.joinToString(",\n", "[\n", "\n${"  ".repeat(depth)}]") { item ->
                    "${"  ".repeat(depth + 1)}${renderJson(item, depth + 1)}"
                }
            }
        }
        is JsonObjectValue -> {
            if (value.values.isEmpty()) {
                "{}"
            } else {
                value.values.entries.joinToString(",\n", "{\n", "\n${"  ".repeat(depth)}}") { (key, item) ->
                    "${"  ".repeat(depth + 1)}${jsonQuote(key)}: ${renderJson(item, depth + 1)}"
                }
            }
        }
    }

fun addJsonRules(json: MutableMap<String, JsonValue>, key: String, additions: List<String>) {
    val existing = jsonArray(JsonObjectValue(json), key)
    json[key] = JsonArrayValue((existing + additions).distinct().map(::JsonStringValue))
}

fun ByteArrayOutputStream.writeVarint(number: Int) {
    require(number >= 0) { "Отрицательное protobuf-число: $number" }
    var remaining = number
    while (remaining >= 0x80) {
        write((remaining and 0x7f) or 0x80)
        remaining = remaining ushr 7
    }
    write(remaining)
}

fun protobufBytes(field: Int, value: ByteArray): ByteArray =
    ByteArrayOutputStream().apply {
        writeVarint((field shl 3) or 2)
        writeVarint(value.size)
        write(value)
    }.toByteArray()

fun protobufNumber(field: Int, value: Int): ByteArray =
    ByteArrayOutputStream().apply {
        writeVarint(field shl 3)
        writeVarint(value)
    }.toByteArray()

fun protobufString(field: Int, value: String): ByteArray =
    protobufBytes(field, value.toByteArray(Charsets.UTF_8))

fun readVarint(bytes: ByteArray, start: Int): Pair<Int, Int> {
    var value = 0
    var offset = start
    var shift = 0
    while (offset < bytes.size && shift <= 28) {
        val byte = bytes[offset++].toInt() and 0xff
        value = value or ((byte and 0x7f) shl shift)
        if (byte < 0x80) {
            return value to offset
        }
        shift += 7
    }
    error("Некорректный protobuf varint в позиции $start")
}

fun geoCategoryNames(bytes: ByteArray): Set<String> {
    val names = mutableSetOf<String>()
    var offset = 0
    while (offset < bytes.size) {
        val (tag, afterTag) = readVarint(bytes, offset)
        check(tag == 10) { "Некорректный protobuf GeoList в позиции $offset" }
        val (length, start) = readVarint(bytes, afterTag)
        check(length > 0 && length <= bytes.size - start) { "Некорректная длина GeoList" }
        val (nameTag, afterNameTag) = readVarint(bytes, start)
        check(nameTag == 10) { "В GeoList отсутствует имя категории" }
        val (nameLength, nameStart) = readVarint(bytes, afterNameTag)
        check(nameLength in 1..128 && nameLength <= start + length - nameStart) { "Некорректное имя категории" }
        val name = String(bytes, nameStart, nameLength, Charsets.UTF_8).uppercase()
        check(names.add(name)) { "Повторяется geo-категория $name" }
        offset = start + length
    }
    return names
}

fun geositeEntry(name: String, rules: List<String>): ByteArray {
    val entry = ByteArrayOutputStream()
    entry.write(protobufString(1, name.uppercase()))
    rules.distinct().forEach { rule ->
        val type = rule.substringBefore(',')
        val value = rule.substringAfter(',', "")
        check(value.isNotEmpty()) { "Некорректное доменное правило: $rule" }
        val domainType =
            when (type) {
                "DOMAIN-KEYWORD" -> 0
                "DOMAIN-SUFFIX" -> 2
                "DOMAIN" -> 3
                else -> error("Нельзя перенести $rule в Happ geosite.dat")
            }
        val domain = ByteArrayOutputStream()
        domain.write(protobufNumber(1, domainType))
        domain.write(protobufString(2, value))
        entry.write(protobufBytes(2, domain.toByteArray()))
    }
    return protobufBytes(1, entry.toByteArray())
}

fun geoipEntry(name: String, ranges: List<String>): ByteArray {
    val entry = ByteArrayOutputStream()
    entry.write(protobufString(1, name.uppercase()))
    ranges.distinct().forEach { range ->
        cidrRule(range, name)
        val address = range.substringBefore('/')
        val prefix = range.substringAfter('/').toInt()
        val cidr = ByteArrayOutputStream()
        cidr.write(protobufBytes(1, InetAddress.getByName(address).address))
        cidr.write(protobufNumber(2, prefix))
        entry.write(protobufBytes(2, cidr.toByteArray()))
    }
    return protobufBytes(1, entry.toByteArray())
}

fun appendGeoEntries(base: ByteArray, entries: List<Pair<String, ByteArray>>): ByteArray {
    val existing = geoCategoryNames(base)
    entries.forEach { (name, _) ->
        check(name.uppercase() !in existing) { "Geo-категория $name уже есть в RoscomVPN" }
    }
    return ByteArrayOutputStream().apply {
        write(base)
        entries.forEach { (_, bytes) -> write(bytes) }
    }.toByteArray()
}

fun pinnedRef(
    sourceUrl: String,
    repository: String,
    assetPath: String,
    fieldName: String
): String {
    val match =
        Regex(
            "^https://cdn\\.jsdelivr\\.net/gh/${Regex.escape(repository)}@([^/]+)/" +
                "${Regex.escape(assetPath)}$"
        ).matchEntire(sourceUrl)
            ?: error("$fieldName должен ссылаться на pinned jsDelivr asset $repository/$assetPath")
    val ref = match.groupValues[1]
    require(Regex("[A-Za-z0-9][A-Za-z0-9._+-]{0,127}").matches(ref)) {
        "Некорректный ref в $fieldName: $ref"
    }
    require(ref !in setOf("HEAD", "main", "master")) { "$fieldName содержит mutable ref: $ref" }
    return ref
}

fun validateCategory(category: String): String {
    require(category.length in 1..128 && Regex("[a-z0-9][a-z0-9._-]*").matches(category)) {
        "Некорректная категория: $category"
    }
    require(".." !in category) { "Некорректная категория: $category" }
    return category
}

fun validateDomain(domain: String, context: String): String {
    require(domain.length in 1..253 && domain == domain.trim()) {
        "Некорректный домен в $context: $domain"
    }
    require(!domain.startsWith('.') && !domain.endsWith('.') && ".." !in domain) {
        "Некорректный домен в $context: $domain"
    }
    domain.split('.').forEach { label ->
        require(label.length in 1..63) { "Некорректная метка домена в $context: $domain" }
        require(label.all { it.isLetterOrDigit() || it == '-' || it == '_' }) {
            "Недопустимый символ домена в $context: $domain"
        }
        require(!label.startsWith('-') && !label.endsWith('-')) {
            "Некорректная метка домена в $context: $domain"
        }
    }
    return domain
}

fun validateDomainKeyword(keyword: String, context: String): String {
    require(keyword.isNotBlank() && keyword.none { it == ',' || it.isWhitespace() || it.isISOControl() }) {
        "Некорректный DOMAIN-KEYWORD в $context: $keyword"
    }
    return keyword
}

fun isValidIpv4(address: String): Boolean {
    val parts = address.split('.')
    return parts.size == 4 &&
        parts.all { part ->
            val number = part.toIntOrNull()
            part.isNotEmpty() &&
                part.all { it.isDigit() } &&
                (part == "0" || !part.startsWith('0')) &&
                number != null &&
                number in 0..255
        }
}

fun isValidIpv6(address: String): Boolean {
    val hasOnlyAddressCharacters =
        address.isNotEmpty() && address.none { character ->
            !character.isDigit() && character.lowercaseChar() !in 'a'..'f' && character !in setOf(':', '.')
        }
    return hasOnlyAddressCharacters &&
        ':' in address &&
        runCatching { InetAddress.getByName(address) }.getOrNull() is Inet6Address
}

fun cidrRule(cidr: String, category: String): String {
    val parts = cidr.split('/')
    require(parts.size == 2 && parts[1].isNotEmpty() && parts[1].all { it.isDigit() }) {
        "Некорректный CIDR в $category: $cidr"
    }

    val address = parts[0]
    val prefix = parts[1].toIntOrNull()
        ?: error("Некорректный CIDR в $category: $cidr")

    return if (':' in address) {
        require(isValidIpv6(address) && prefix in 0..128) {
            "Некорректный IPv6 CIDR в $category: $cidr"
        }
        "IP-CIDR6,$cidr"
    } else {
        require(isValidIpv4(address) && prefix in 0..32) {
            "Некорректный IPv4 CIDR в $category: $cidr"
        }
        "IP-CIDR,$cidr"
    }
}

fun dnsScopesOverlap(first: String, second: String): Boolean =
    first == second || first.endsWith(".$second") || second.endsWith(".$first")

fun alwaysRealPatternOverlapsZone(pattern: String, zone: String): Boolean {
    val normalizedPattern = pattern.lowercase().trimEnd('.')
    val normalizedZone = zone.lowercase().trimEnd('.')
    val lastWildcardIndex = maxOf(normalizedPattern.lastIndexOf('*'), normalizedPattern.lastIndexOf('?'))
    val fixedSuffix =
        if (lastWildcardIndex >= 0) {
            normalizedPattern.substring(lastWildcardIndex + 1).trimStart('.')
        } else {
            normalizedPattern
        }
    return fixedSuffix.isEmpty() || dnsScopesOverlap(fixedSuffix, normalizedZone)
}

fun replaceUniqueMarker(
    template: String,
    marker: String,
    replacement: String,
    templatePath: Path
): String {
    val markerIndex = template.indexOf(marker)
    check(markerIndex >= 0 && markerIndex == template.lastIndexOf(marker)) {
        "В ${templatePath.fileName} отсутствует единственный маркер $marker"
    }
    return template.replace(marker, replacement)
}

fun normalizedLines(text: String): List<String> =
    text
        .lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .toList()

fun existingRuleCount(path: Path): Int? =
    if (Files.isRegularFile(path)) {
        Files
            .readString(path)
            .lineSequence()
            .count { line -> line.isNotBlank() && !line.startsWith("#") }
    } else {
        null
    }

fun validateGeneratedRuleCount(
    path: Path,
    rules: List<String>
) {
    check(rules.isNotEmpty()) {
        "Список ${path.fileName} неожиданно пуст"
    }

    val previousRuleCount = existingRuleCount(path)

    if (previousRuleCount != null && previousRuleCount > 0) {
        check(rules.size.toLong() * 100 >= previousRuleCount.toLong() * 70) {
            "Список ${path.fileName} резко уменьшился: $previousRuleCount -> ${rules.size}"
        }
    }
}

fun regexRule(pattern: String, category: String): List<String> =
    when (pattern) {
        "^github-production-release-asset-[0-9a-zA-Z]{6}\\.s3\\.amazonaws\\.com\$" ->
            listOf("DOMAIN-WILDCARD,github-production-release-asset-??????.s3.amazonaws.com")
        "^[a-z]([a-z0-9-]{0,61}[a-z0-9])?\$" -> {
            check(category == "private") { "Неожиданное односегментное regexp в $category" }
            emptyList()
        }
        else -> error("Неподдерживаемое regexp в $category: $pattern")
    }

fun geositeRules(
    category: String,
    geositeBaseUrl: String,
    visited: MutableSet<String> = mutableSetOf()
): List<String> {
    validateCategory(category)
    check(visited.add(category)) { "Циклический include в geosite: $category" }

    val sourceUrl = "$geositeBaseUrl/$category"
    val rules =
        normalizedLines(download(sourceUrl)).flatMap { sourceLine ->
            val line =
                sourceLine
                    .substringBefore(" #")
                    .substringBefore(" @")
                    .trim()

            when {
                line.startsWith("include:") ->
                    geositeRules(line.removePrefix("include:"), geositeBaseUrl, visited)
                line.startsWith("domain:") ->
                    listOf("DOMAIN-SUFFIX,${validateDomain(line.removePrefix("domain:"), category)}")
                line.startsWith("full:") ->
                    listOf("DOMAIN,${validateDomain(line.removePrefix("full:"), category)}")
                line.startsWith("keyword:") ->
                    listOf("DOMAIN-KEYWORD,${validateDomainKeyword(line.removePrefix("keyword:"), category)}")
                line.startsWith("regexp:") -> {
                    val pattern = line.removePrefix("regexp:")
                    regexRule(pattern, category)
                }
                ":" !in line -> listOf("DOMAIN-SUFFIX,${validateDomain(line, category)}")
                else -> error("Неподдерживаемая строка в $category: $line")
            }
        }

    visited.remove(category)
    return rules
}

fun geoipRules(category: String, geoipBaseUrl: String): List<String> {
    validateCategory(category)
    return normalizedLines(download("$geoipBaseUrl/$category.txt")).map { cidr -> cidrRule(cidr, category) }
}

fun alwaysRealIpPatterns(category: String, geositeBaseUrl: String): List<String> =
    geositeRules(category, geositeBaseUrl)
        .flatMap { rule ->
            val separatorIndex = rule.indexOf(',')
            check(separatorIndex > 0) { "Некорректное доменное правило в $category: $rule" }

            val type = rule.substring(0, separatorIndex)
            val value = rule.substring(separatorIndex + 1)
            when (type) {
                "DOMAIN" -> listOf(value)
                "DOMAIN-SUFFIX" -> listOf(value, "*.$value")
                "DOMAIN-WILDCARD" -> listOf(value)
                else -> error("Нельзя преобразовать $rule в always-real-ip")
            }
        }
        .distinct()
        .sorted()

fun categoryName(reference: String, prefix: String): String {
    val expectedPrefix = "$prefix:"
    require(reference.startsWith(expectedPrefix)) {
        "Ожидалась ссылка $expectedPrefix, получено: $reference"
    }
    return validateCategory(reference.removePrefix(expectedPrefix))
}

val routingSource =
    System.getenv("ROUTING_SOURCE_FILE")?.let { path -> Files.readString(Path.of(path)) }
        ?: download(routingUrl)
val routing = StrictJsonParser(routingSource).parseDocument()
val lastUpdated = jsonString(routing, "LastUpdated")
check(lastUpdated.isNotEmpty() && lastUpdated.all { it.isDigit() }) {
    "LastUpdated должен содержать Unix timestamp: $lastUpdated"
}
check(jsonString(routing, "GlobalProxy") == "true") {
    "Поддерживается только GlobalProxy=true"
}
check(jsonString(routing, "RouteOrder") == "block-proxy-direct") {
    "Поддерживается только RouteOrder=block-proxy-direct"
}
check(jsonString(routing, "DomainStrategy") == "IPIfNonMatch") {
    "Поддерживается только DomainStrategy=IPIfNonMatch"
}

val geositeRef =
    pinnedRef(
        sourceUrl = jsonString(routing, "Geositeurl"),
        repository = "hydraponique/roscomvpn-geosite",
        assetPath = "release/geosite.dat",
        fieldName = "Geositeurl"
    )
val geoipRef =
    pinnedRef(
        sourceUrl = jsonString(routing, "Geoipurl"),
        repository = "hydraponique/roscomvpn-geoip",
        assetPath = "release/geoip.dat",
        fieldName = "Geoipurl"
    )
val geositeBaseUrl =
    "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite@$geositeRef/data"
val geoipBaseUrl =
    "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip@$geoipRef/release/text"

val dnsHosts = sortedMapOf<String, String>()
jsonStringMap(routing, "DnsHosts").forEach { (host, address) ->
    val normalizedHost = validateDomain(host, "DnsHosts").lowercase()
    require(isValidIpv4(address)) {
        "DnsHosts поддерживает только корректный IPv4: $host = $address"
    }
    check(dnsHosts.put(normalizedHost, address) == null) {
        "В DnsHosts повторяется домен без учёта регистра: $host"
    }
}
check(dnsHosts.isNotEmpty()) { "DnsHosts неожиданно пуст" }

val specs =
    listOf(
        RouteSpec(
            name = "BLOCK",
            domainFileName = "BLOCK_DOMAIN.list",
            ipFileName = "BLOCK_IP.list",
            siteKey = "BlockSites",
            ipKey = "BlockIp",
            minimumRuleCount = 100
        ),
        RouteSpec(
            name = "PROXY",
            domainFileName = "PROXY_DOMAIN.list",
            ipFileName = "PROXY_IP.list",
            siteKey = "ProxySites",
            ipKey = "ProxyIp",
            minimumRuleCount = 50
        ),
        RouteSpec(
            name = "DIRECT",
            domainFileName = "DIRECT_DOMAIN.list",
            ipFileName = "DIRECT_IP.list",
            siteKey = "DirectSites",
            ipKey = "DirectIp",
            minimumRuleCount = 1_000
        )
    )

val outputDirectory = Path.of("rules")
val generatedFiles = linkedMapOf<Path, String>()
val generatedBinaryFiles = linkedMapOf<Path, ByteArray>()
val generatedRuleCounts = linkedMapOf<String, Int>()
val generatedIpRuleSets = mutableMapOf<String, Boolean>()
val preservedDirectIpPath = outputDirectory.resolve("DIRECT_IP.list")
check(Files.isRegularFile(preservedDirectIpPath)) { "Отсутствует закреплённый DIRECT_IP.list" }
val preservedDirectIpRules = normalizedLines(Files.readString(preservedDirectIpPath))
check(preservedDirectIpRules.size >= 30_000) { "Закреплённый DIRECT_IP.list неожиданно мал" }
check(preservedDirectIpRules.all { it.startsWith("IP-CIDR,") || it.startsWith("IP-CIDR6,") }) {
    "Закреплённый DIRECT_IP.list содержит не IP-CIDR правило"
}

specs.forEach { spec ->
    val siteCategories =
        jsonArray(routing, spec.siteKey)
            .map { categoryName(it, "geosite") }

    val ipCategories =
        jsonArray(routing, spec.ipKey)
            .map { categoryName(it, "geoip") }

    val domainRules =
        siteCategories
            .flatMap { geositeRules(it, geositeBaseUrl) }
            .distinct()
            .sorted()

    val ipRules =
        ipCategories
            .flatMap { geoipRules(it, geoipBaseUrl) }
            .distinct()
            .sorted()

    check(domainRules.all { it.startsWith("DOMAIN") }) {
        "${spec.domainFileName} содержит не DOMAIN-правило"
    }

    check(ipRules.all { it.startsWith("IP-CIDR") }) {
        "${spec.ipFileName} содержит не IP-CIDR правило"
    }

    check(ipRules.none { it.endsWith(",no-resolve") }) {
        "${spec.ipFileName} не должен содержать no-resolve: это IPIfNonMatch-фаза"
    }

    val totalRuleCount = domainRules.size + ipRules.size

    check(totalRuleCount >= spec.minimumRuleCount) {
        """
        Категория ${spec.name} содержит только $totalRuleCount правил.
        DOMAIN: ${domainRules.size}
        IP: ${ipRules.size}
        Минимум: ${spec.minimumRuleCount}
        """.trimIndent()
    }

    val domainPath = outputDirectory.resolve(spec.domainFileName)
    val ipPath = outputDirectory.resolve(spec.ipFileName)

    validateGeneratedRuleCount(domainPath, domainRules)

    val domainContent =
        buildString {
            appendLine("# Автоматически сгенерировано из RoscomVPN")
            appendLine("# LastUpdated: $lastUpdated")
            appendLine("# Geosite ref: $geositeRef")
            appendLine("# Geosite: ${siteCategories.joinToString()}")
            appendLine("# Phase: DOMAIN")
            domainRules.forEach { appendLine(it) }
        }

    generatedFiles[domainPath] = domainContent
    generatedRuleCounts[spec.domainFileName] = domainRules.size

    val hasIpCategories = ipCategories.isNotEmpty()

    if (hasIpCategories) {
        check(ipRules.isNotEmpty()) {
            "${spec.ipFileName} должен содержать IP-правила, потому что ${spec.ipKey} не пуст"
        }
    }

    generatedIpRuleSets[spec.name] = hasIpCategories

    if (hasIpCategories && spec.name == "DIRECT") {
        // Сохраняем проверенный DirectIp: upstream резко сократил список 25 октября 2026 года.
        generatedRuleCounts[spec.ipFileName] = preservedDirectIpRules.size
    } else if (hasIpCategories) {
        validateGeneratedRuleCount(ipPath, ipRules)

        val ipContent =
            buildString {
                appendLine("# Автоматически сгенерировано из RoscomVPN")
                appendLine("# LastUpdated: $lastUpdated")
                appendLine("# GeoIP ref: $geoipRef")
                appendLine("# GeoIP: ${ipCategories.joinToString()}")
                appendLine("# Phase: IP")
                ipRules.forEach { appendLine(it) }
            }

        generatedFiles[ipPath] = ipContent
        generatedRuleCounts[spec.ipFileName] = ipRules.size
    } else {
        // Если раньше файл существовал, но upstream теперь убрал IP-правила,
        // удаляем устаревший файл.
        Files.deleteIfExists(ipPath)
    }
}

val directSiteCategories = jsonArray(routing, "DirectSites").map { categoryName(it, "geosite") }
check("whitelist" in directSiteCategories) {
    "В DirectSites отсутствует обязательная категория geosite:whitelist"
}
val directIpCategories = jsonArray(routing, "DirectIp").map { categoryName(it, "geoip") }
check("private" in directIpCategories) {
    "В DirectIp отсутствует обязательная категория geoip:private"
}

val ipCheckProxyDomains =
    setOf(
        "2ip.ru",
        "checkip.amazonaws.com",
        "ifconfig.me",
        "ip.sb",
        "ipapi.is",
        "ipify.org",
        "iplocate.io",
        "showip.net"
    )
val protectedAlwaysRealIpZones = ipCheckProxyDomains + setOf("yandexcloud.net")
dnsHosts.keys.forEach { host ->
    check(protectedAlwaysRealIpZones.none { zone -> alwaysRealPatternOverlapsZone(host, zone) }) {
        "DnsHosts-домен $host конфликтует с защищённой зоной always-real-ip"
    }
}
val alwaysRealIpCandidates =
    (alwaysRealIpPatterns("whitelist", geositeBaseUrl) + dnsHosts.keys)
        .distinct()
        .sorted()
val shadowrocketAlwaysRealIpPatterns =
    alwaysRealIpCandidates.filterNot { pattern ->
        protectedAlwaysRealIpZones.any { zone -> alwaysRealPatternOverlapsZone(pattern, zone) }
    }
check(shadowrocketAlwaysRealIpPatterns.isNotEmpty()) { "Список always-real-ip получился пустым" }
check("*.netmonet.co" in shadowrocketAlwaysRealIpPatterns) {
    "В geosite:whitelist отсутствует ожидаемый домен netmonet.co"
}
protectedAlwaysRealIpZones.forEach { zone ->
    check(shadowrocketAlwaysRealIpPatterns.none { pattern -> alwaysRealPatternOverlapsZone(pattern, zone) }) {
        "$zone не должен отключать Fake-IP через always-real-ip"
    }
}
dnsHosts.keys.forEach { host ->
    check(host in shadowrocketAlwaysRealIpPatterns) {
        "DnsHosts-домен $host отсутствует в always-real-ip"
    }
}

val additionalRejectUrl =
    "https://raw.githubusercontent.com/zeklop/shadowrocket-configs/main/REJECT.list"

val additionalRejectRules =
    normalizedLines(
        System.getenv("REJECT_SOURCE_FILE")?.let { path -> Files.readString(Path.of(path)) }
            ?: download(additionalRejectUrl)
    )

val allowedDomainRulePrefixes =
    listOf(
        "DOMAIN,",
        "DOMAIN-SUFFIX,",
        "DOMAIN-KEYWORD,"
    )

check(
    additionalRejectRules.all { rule ->
        allowedDomainRulePrefixes.any { prefix -> rule.startsWith(prefix) }
    }
) {
    "В REJECT.list появилось не DOMAIN-правило. " +
            "Такой список нельзя размещать в DOMAIN-фазе IPIfNonMatch."
}

val templatePath = Path.of("shadowrocket.template.conf")
val alwaysRealIpMarker = "{{ROSCOMVPN_WHITELIST_ALWAYS_REAL_IP}}"
val dnsHostsSectionMarker = "{{ROSCOMVPN_DNS_HOSTS_SECTION}}"
val blockIpRuleSetMarker = "{{ROSCOMVPN_BLOCK_IP_RULESET}}"
val proxyIpRuleSetMarker = "{{ROSCOMVPN_PROXY_IP_RULESET}}"
val configTemplate = Files.readString(templatePath)
val templateRuleLines = configTemplate.lineSequence().map { it.trim() }.toSet()
ipCheckProxyDomains.forEach { domain ->
    check("DOMAIN-SUFFIX,$domain,PROXY" in templateRuleLines) {
        "В ${templatePath.fileName} нет PROXY-правила для $domain"
    }
}

val dnsHostsSection =
    buildString {
        appendLine("[Host]")
        dnsHosts.forEach { (host, address) -> appendLine("$host = $address") }
    }.trimEnd()

val blockIpRuleSet =
    if (generatedIpRuleSets["BLOCK"] == true) {
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/BLOCK_IP.list,REJECT"
    } else {
        ""
    }

val proxyIpRuleSet =
    if (generatedIpRuleSets["PROXY"] == true) {
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/PROXY_IP.list,PROXY"
    } else {
        ""
    }

val configWithAlwaysRealIp =
    replaceUniqueMarker(
        template = configTemplate,
        marker = alwaysRealIpMarker,
        replacement = shadowrocketAlwaysRealIpPatterns.joinToString(", "),
        templatePath = templatePath
    )

val configWithDnsHosts =
    replaceUniqueMarker(
        template = configWithAlwaysRealIp,
        marker = dnsHostsSectionMarker,
        replacement = dnsHostsSection,
        templatePath = templatePath
    )

val configWithBlockIp =
    replaceUniqueMarker(
        template = configWithDnsHosts,
        marker = blockIpRuleSetMarker,
        replacement = blockIpRuleSet,
        templatePath = templatePath
    )

val shadowrocketConfig =
    replaceUniqueMarker(
        template = configWithBlockIp,
        marker = proxyIpRuleSetMarker,
        replacement = proxyIpRuleSet,
        templatePath = templatePath
    )
val generatedConfigRuleLines =
    shadowrocketConfig
        .lineSequence()
        .map { it.trim() }
        .toList()
val generatedConfigLines = generatedConfigRuleLines.toSet()
check("{{ROSCOMVPN_" !in shadowrocketConfig) {
    "В shadowrocket.conf остался незаменённый marker"
}
check("dns-direct-fallback-proxy = false" in generatedConfigLines) {
    "DIRECT DNS не должен переключаться на proxy fallback"
}
check("private-ip-answer = true" in generatedConfigLines) {
    "Shadowrocket должен принимать private DNS-ответы для IPIfNonMatch"
}

val blockDomainIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/BLOCK_DOMAIN.list,REJECT"
    )

val proxyDomainIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/PROXY_DOMAIN.list,PROXY"
    )

val reFilterDomainIndex =
    generatedConfigRuleLines.indexOf(
        "DOMAIN-SET,https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst,PROXY"
    )

val directDomainIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/DIRECT_DOMAIN.list,DIRECT"
    )

val nationalZoneFallbackIndex =
    generatedConfigRuleLines.indexOf("DOMAIN-SUFFIX,by,DIRECT")

val blockIpIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/BLOCK_IP.list,REJECT"
    )

val proxyIpIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/PROXY_IP.list,PROXY"
    )

val reFilterIpIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst,PROXY"
    )

val directIpIndex =
    generatedConfigRuleLines.indexOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/rules/DIRECT_IP.list,DIRECT"
    )

val geoIpFallbackIndex =
    generatedConfigRuleLines.indexOf("GEOIP,RU,DIRECT")

val finalProxyIndex =
    generatedConfigRuleLines.indexOf("FINAL,PROXY")

check(
    listOf(
        blockDomainIndex,
        proxyDomainIndex,
        reFilterDomainIndex,
        directDomainIndex,
        nationalZoneFallbackIndex,
        reFilterIpIndex,
        directIpIndex,
        geoIpFallbackIndex,
        finalProxyIndex
    ).all { it >= 0 }
) {
    "В shadowrocket.conf отсутствуют обязательные IPIfNonMatch-правила"
}

check(
    (generatedIpRuleSets["BLOCK"] == true) == (blockIpIndex >= 0)
) {
    "BLOCK_IP RULE-SET не соответствует текущему BlockIp"
}

check(
    (generatedIpRuleSets["PROXY"] == true) == (proxyIpIndex >= 0)
) {
    "PROXY_IP RULE-SET не соответствует текущему ProxyIp"
}

val domainPhaseIndices =
    listOf(
        blockDomainIndex,
        proxyDomainIndex,
        reFilterDomainIndex,
        directDomainIndex,
        nationalZoneFallbackIndex
    )

check(
    domainPhaseIndices.zipWithNext().all { (first, second) ->
        first < second
    }
) {
    "Нарушен порядок DOMAIN-фазы"
}

val ipPhaseIndices =
    buildList {
        if (blockIpIndex >= 0) {
            add(blockIpIndex)
        }

        if (proxyIpIndex >= 0) {
            add(proxyIpIndex)
        }

        add(reFilterIpIndex)
        add(directIpIndex)
        add(geoIpFallbackIndex)
        add(finalProxyIndex)
    }

check(
    nationalZoneFallbackIndex < ipPhaseIndices.first()
) {
    "IP-фаза должна начинаться только после всех DOMAIN-правил"
}

check(
    ipPhaseIndices.zipWithNext().all { (first, second) ->
        first < second
    }
) {
    "Нарушен порядок IPIfNonMatch/fallback-фазы"
}

generatedFiles[Path.of("shadowrocket.conf")] = shadowrocketConfig

val reFilterBaseUrl = "https://cdn.jsdelivr.net/gh/1andrevich/Re-filter-lists@main"
val reFilterDomainRules =
    listOf("domains_all.lst", "community.lst")
        .flatMap { fileName ->
            normalizedLines(download("$reFilterBaseUrl/$fileName"))
                .map { domain -> "DOMAIN-SUFFIX,${validateDomain(domain, fileName)}" }
        }
        .distinct()
val reFilterIpRanges =
    listOf("ipsum.lst", "community_ips.lst", "discord_ips.lst")
        .flatMap { fileName -> normalizedLines(download("$reFilterBaseUrl/$fileName")) }
        .distinct()
val russianIpRanges =
    normalizedLines(download("https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/ru.txt"))
        .distinct()
check(reFilterDomainRules.size >= 50_000) { "Re-filter неожиданно потерял домены" }
check(reFilterIpRanges.size >= 20_000) { "Re-filter неожиданно потерял IP-диапазоны" }
check(russianIpRanges.size >= 15_000) { "GeoIP RU неожиданно потерял IP-диапазоны" }

val happGeosite =
    appendGeoEntries(
        downloadBytes(jsonString(routing, "Geositeurl")),
        listOf(
            "SHADOWROCKET-REJECT" to geositeEntry("SHADOWROCKET-REJECT", additionalRejectRules),
            "SHADOWROCKET-PROXY" to geositeEntry("SHADOWROCKET-PROXY", reFilterDomainRules)
        )
    )
val happGeoip =
    appendGeoEntries(
        downloadBytes(jsonString(routing, "Geoipurl")),
        listOf(
            "SHADOWROCKET-PROXY" to geoipEntry("SHADOWROCKET-PROXY", reFilterIpRanges),
            "SHADOWROCKET-DIRECT" to geoipEntry(
                "SHADOWROCKET-DIRECT",
                preservedDirectIpRules.map { rule -> rule.substringAfter(',') }
            ),
            "RU" to geoipEntry("RU", russianIpRanges)
        )
    )
check(geoCategoryNames(happGeosite).containsAll(setOf("SHADOWROCKET-REJECT", "SHADOWROCKET-PROXY"))) {
    "В Happ geosite.dat отсутствуют дополнительные категории"
}
check(geoCategoryNames(happGeoip).containsAll(setOf("SHADOWROCKET-PROXY", "SHADOWROCKET-DIRECT", "RU"))) {
    "В Happ geoip.dat отсутствуют дополнительные категории"
}

val happFields = routing.values.toMutableMap()
happFields["Name"] = JsonStringValue("Shadowrocket-like Happ")
happFields["Geositeurl"] =
    JsonStringValue(
        "https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/happ/geosite.dat"
    )
happFields["Geoipurl"] =
    JsonStringValue(
        "https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/happ/geoip.dat"
    )
addJsonRules(happFields, "BlockSites", listOf("geosite:shadowrocket-reject"))
addJsonRules(
    happFields,
    "ProxySites",
    listOf("geosite:shadowrocket-proxy") + ipCheckProxyDomains.sorted().map { domain -> "domain:$domain" }
)
addJsonRules(happFields, "ProxyIp", listOf("geoip:shadowrocket-proxy"))
addJsonRules(happFields, "DirectSites", listOf("domain:ru", "domain:xn--p1ai", "domain:su", "domain:by"))
check(jsonArray(routing, "DirectIp") == listOf("geoip:private", "geoip:direct")) {
    "Состав DirectIp upstream изменился; закреплённый Happ-профиль требует проверки"
}
happFields["DirectIp"] =
    JsonArrayValue(
        listOf("geoip:private", "geoip:shadowrocket-direct", "geoip:ru").map(::JsonStringValue)
    )
val previousHappPath = Path.of("happ/happ-routing.json")
val previousHapp =
    if (Files.isRegularFile(previousHappPath)) {
        StrictJsonParser(Files.readString(previousHappPath)).parseDocument()
    } else {
        null
    }
val previousHappTimestamp =
    (previousHapp?.values?.get("LastUpdated") as? JsonStringValue)?.value?.toLongOrNull() ?: 0L
val happDataChanged =
    previousHapp?.values?.filterKeys { key -> key != "LastUpdated" } !=
        happFields.filterKeys { key -> key != "LastUpdated" } ||
        !Files.isRegularFile(Path.of("happ/geosite.dat")) ||
        !Files.readAllBytes(Path.of("happ/geosite.dat")).contentEquals(happGeosite) ||
        !Files.isRegularFile(Path.of("happ/geoip.dat")) ||
        !Files.readAllBytes(Path.of("happ/geoip.dat")).contentEquals(happGeoip)
val happTimestamp =
    if (happDataChanged) {
        maxOf(lastUpdated.toLong(), previousHappTimestamp + 1, System.currentTimeMillis() / 1_000)
    } else {
        maxOf(lastUpdated.toLong(), previousHappTimestamp)
    }
happFields["LastUpdated"] = JsonStringValue(happTimestamp.toString())
val happJson = "${renderJson(JsonObjectValue(happFields))}\n"
val happLink =
    "happ://routing/add/${Base64.getEncoder().encodeToString(happJson.toByteArray(Charsets.UTF_8))}\n"
generatedFiles[Path.of("happ/happ-routing.json")] = happJson
generatedFiles[Path.of("happ/happ-routing-link.txt")] = happLink
generatedBinaryFiles[Path.of("happ/geosite.dat")] = happGeosite
generatedBinaryFiles[Path.of("happ/geoip.dat")] = happGeoip

val legacyRuleFiles =
    listOf(
        "BLOCK.list",
        "PROXY.list",
        "DIRECT.list"
    )

legacyRuleFiles.forEach { fileName ->
    Files.deleteIfExists(outputDirectory.resolve(fileName))
}

Files.createDirectories(outputDirectory)
Files.createDirectories(Path.of("happ"))
generatedFiles.forEach { (path, content) -> Files.writeString(path, content) }
generatedBinaryFiles.forEach { (path, content) -> Files.write(path, content) }
generatedRuleCounts.forEach { (fileName, count) -> println("$fileName: $count правил") }
println("shadowrocket.conf: ${shadowrocketAlwaysRealIpPatterns.size} шаблонов always-real-ip")
println("shadowrocket.conf: ${dnsHosts.size} записей DnsHosts")
println("happ: ${reFilterDomainRules.size} Re-filter доменов")
println("happ: ${reFilterIpRanges.size} Re-filter IP-диапазонов")
