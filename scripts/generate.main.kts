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
import java.time.Instant
import java.util.Base64

val httpClient =
    HttpClient
        .newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

val downloadCache = mutableMapOf<String, String>()

fun download(url: String): String {
    downloadCache[url]?.let { return it }
    var lastFailure = "неизвестная ошибка"

    repeat(4) { attempt ->
        val requestBuilder =
            HttpRequest
                .newBuilder(URI.create(url))
                .header("User-Agent", "independent-ru-routing")
                .timeout(Duration.ofSeconds(60))
        if (URI.create(url).host == "api.github.com") {
            System.getenv("GITHUB_TOKEN")?.takeIf { it.isNotBlank() }?.let { token ->
                requestBuilder.header("Authorization", "Bearer $token")
            }
        }
        val request = requestBuilder.GET().build()
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
            ?: error("Корневое значение JSON должно быть объектом")
    }

    fun parseArrayDocument(): JsonArrayValue {
        val value = parseValue()
        skipWhitespace()
        check(index == source.length) {
            "После JSON обнаружены лишние данные в позиции $index"
        }
        return value as? JsonArrayValue
            ?: error("Корневое значение ответа GitHub должно быть массивом")
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
    val value = json.values[key] ?: error("В JSON отсутствует поле $key")
    return (value as? JsonStringValue)?.value ?: error("Поле $key должно быть строкой")
}

fun jsonObject(json: JsonObjectValue, key: String): JsonObjectValue =
    json.values[key] as? JsonObjectValue
        ?: error("Поле $key должно быть объектом")

fun commitDate(commit: JsonObjectValue): Instant =
    Instant.parse(jsonString(jsonObject(jsonObject(commit, "commit"), "committer"), "date"))

fun latestBranchCommit(repository: String, branch: String): String {
    require(Regex("[A-Za-z0-9._-]+/[A-Za-z0-9._-]+").matches(repository)) {
        "Некорректный GitHub-репозиторий: $repository"
    }
    require(branch in setOf("main", "master", "release")) { "Неизвестная ветка: $branch" }
    val response = StrictJsonParser(download("https://api.github.com/repos/$repository/commits/$branch"))
        .parseDocument()
    val sha = jsonString(response, "sha")
    check(Regex("[a-f0-9]{40}").matches(sha)) {
        "Некорректный SHA коммита $repository/$branch: $sha"
    }
    return sha
}

fun latestFileChangeDate(repository: String, path: String, commit: String): Instant {
    require(Regex("[a-f0-9]{40}").matches(commit)) { "Некорректный SHA для $repository/$path" }
    val url = "https://api.github.com/repos/$repository/commits?path=$path&sha=$commit&per_page=1"
    val commits = StrictJsonParser(download(url)).parseArrayDocument().values
    val firstCommit = commits.singleOrNull() as? JsonObjectValue
        ?: error("GitHub не вернул коммит $repository/$path")
    return commitDate(firstCommit)
}

fun reportSourceFreshness(name: String, updatedAt: Instant, maxAge: Duration) {
    val age = Duration.between(updatedAt, Instant.now())
    if (age.isNegative) {
        println("::warning::Источник $name имеет дату из будущего: $updatedAt")
        return
    }
    if (age > maxAge) {
        val message = "Источник $name не менялся ${age.toDays()} дн. (последний коммит $updatedAt)"
        println("::warning::$message")
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

fun matchesDomainRule(rule: String, hostname: String): Boolean {
    val type = rule.substringBefore(',')
    val value = rule.substringAfter(',', "")
    return when (type) {
        "DOMAIN" -> hostname == value
        "DOMAIN-SUFFIX" -> hostname == value || hostname.endsWith(".$value")
        "DOMAIN-KEYWORD" -> value in hostname
        else -> false
    }
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

fun normalizedLines(text: String): List<String> =
    text
        .lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .toList()

fun existingRules(path: Path): Set<String>? =
    if (Files.isRegularFile(path)) {
        Files
            .readString(path)
            .lineSequence()
            .filter { line -> line.isNotBlank() && !line.startsWith("#") }
            .toSet()
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

    val previousRules = existingRules(path)
    if (previousRules != null && previousRules.isNotEmpty()) {
        val previousRuleCount = previousRules.size
        check(rules.size.toLong() * 100 >= previousRuleCount.toLong() * 70) {
            "Список ${path.fileName} резко уменьшился: $previousRuleCount -> ${rules.size}"
        }
        check(rules.size.toLong() * 100 <= previousRuleCount.toLong() * 130) {
            "Список ${path.fileName} резко вырос: $previousRuleCount -> ${rules.size}"
        }
        val retainedRules = rules.toSet().intersect(previousRules).size
        check(retainedRules.toLong() * 100 >= previousRuleCount.toLong() * 80 &&
            retainedRules.toLong() * 100 >= rules.size.toLong() * 80
        ) {
            "Список ${path.fileName} заменил слишком много правил: сохранено $retainedRules из $previousRuleCount"
        }
    }
}

fun previousSourceCounts(path: Path): Map<String, Int> =
    if (Files.isRegularFile(path)) {
        Files
            .readAllLines(path)
            .filter { line -> '=' in line && !line.startsWith('#') }
            .mapNotNull { line ->
                val count = line.substringAfter('=').toIntOrNull()
                count?.let { line.substringBefore('=') to it }
            }
            .toMap()
    } else {
        emptyMap()
    }

fun validateSourceCount(name: String, count: Int, previous: Map<String, Int>) {
    check(count > 0) { "Источник $name неожиданно пуст" }
    previous[name]?.takeIf { it > 0 }?.let { old ->
        check(count.toLong() * 100 >= old.toLong() * 70) {
            "Источник $name резко уменьшился: $old -> $count"
        }
        check(count.toLong() * 100 <= old.toLong() * 130) {
            "Источник $name резко вырос: $old -> $count"
        }
    }
}

var taggedDomainRulesSkipped = 0
var knownOpenaiRegexSkipped = 0
var knownEpicRegexSkipped = 0

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
                    .trim()
            if (Regex("\\s@").containsMatchIn(line)) {
                taggedDomainRulesSkipped++
                return@flatMap emptyList<String>()
            }
            if (category == "openai" &&
                line == """regexp:^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"""
            ) {
                knownOpenaiRegexSkipped++
                return@flatMap emptyList<String>()
            }
            if (category == "epicgames" &&
                line == """regexp:^epicgames-download\d\.akamaized\.net$"""
            ) {
                knownEpicRegexSkipped++
                return@flatMap emptyList<String>()
            }

            when {
                line.startsWith("include:") ->
                    geositeRules(line.removePrefix("include:"), geositeBaseUrl, visited)
                line.startsWith("domain:") ->
                    listOf("DOMAIN-SUFFIX,${validateDomain(line.removePrefix("domain:"), category)}")
                line.startsWith("full:") ->
                    listOf("DOMAIN,${validateDomain(line.removePrefix("full:"), category)}")
                line.startsWith("keyword:") ->
                    listOf("DOMAIN-KEYWORD,${validateDomainKeyword(line.removePrefix("keyword:"), category)}")
                line.startsWith("regexp:") -> error("Неподдерживаемое regexp в $category: $line")
                ":" !in line -> listOf("DOMAIN-SUFFIX,${validateDomain(line, category)}")
                else -> error("Неподдерживаемая строка в $category: $line")
            }
        }

    visited.remove(category)
    return rules
}

val rulesDirectory = Path.of("rules")
val manifestPath = rulesDirectory.resolve("SOURCE_MANIFEST.txt")
val previousManifest = if (Files.isRegularFile(manifestPath)) Files.readString(manifestPath) else ""
val previousCounts = previousSourceCounts(manifestPath)
val samePolicyVersion = "source_profile=independent-v1" in previousManifest
val generatedFiles = linkedMapOf<Path, String>()
val generatedBinaryFiles = linkedMapOf<Path, ByteArray>()
val generatedValidationFiles = linkedMapOf<Path, String>()

val priorityPath = rulesDirectory.resolve("DIRECT_PRIORITY_DOMAIN.list")
val priorityDomains =
    normalizedLines(Files.readString(priorityPath))
        .map { rule ->
            require(rule.startsWith("DOMAIN-SUFFIX,")) {
                "Приоритетное правило должно быть DOMAIN-SUFFIX: $rule"
            }
            val domain = validateDomain(rule.removePrefix("DOMAIN-SUFFIX,"), priorityPath.fileName.toString())
            require('.' in domain) { "Приоритетное правило слишком широкое: $domain" }
            domain
        }
        .distinct()
check(priorityDomains.isNotEmpty()) { "DIRECT_PRIORITY_DOMAIN.list пуст" }

val v2flyCommit = latestBranchCommit("v2fly/domain-list-community", "master")
val reFilterCommit = latestBranchCommit("1andrevich/Re-filter-lists", "main")
val ruGeoipCommit = latestBranchCommit("Loyalsoldier/geoip", "release")
val v2flyBaseUrl =
    "https://raw.githubusercontent.com/v2fly/domain-list-community/$v2flyCommit/data"
val reFilterBaseUrl =
    "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/$reFilterCommit"
val ruGeoipUrl =
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/$ruGeoipCommit/text/ru.txt"

val v2flyDirectUpdatedAt = latestFileChangeDate("v2fly/domain-list-community", "data/category-ru", v2flyCommit)
val reFilterUpdatedAt = latestFileChangeDate("1andrevich/Re-filter-lists", "domains_all.lst", reFilterCommit)
val ruGeoipUpdatedAt = latestFileChangeDate("Loyalsoldier/geoip", "text/ru.txt", ruGeoipCommit)
reportSourceFreshness("v2fly category-ru", v2flyDirectUpdatedAt, Duration.ofDays(45))
reportSourceFreshness("Re-filter domains_all.lst", reFilterUpdatedAt, Duration.ofDays(14))
reportSourceFreshness("RU GeoIP", ruGeoipUpdatedAt, Duration.ofDays(14))

val proxyCategories = listOf("youtube", "telegram", "github", "instagram", "discord", "google-play", "openai")
val proxyCategoryRules =
    proxyCategories
        .flatMap { category -> geositeRules(category, v2flyBaseUrl) }
        .distinct()
        .sorted()
val manualProxyRules = listOf("DOMAIN-KEYWORD,chatgpt-async-webps-prod-")
val proxyDomainRules = (proxyCategoryRules + manualProxyRules).distinct().sorted()
val directDomainRules =
    geositeRules("category-ru", v2flyBaseUrl)
        .distinct()
        .sorted()
val directForeignCategories =
    listOf("microsoft", "apple", "epicgames", "riot", "escapefromtarkov", "steam", "twitch", "pinterest", "faceit")
val foreignCategoryRules =
    directForeignCategories
        .flatMap { category -> geositeRules(category, v2flyBaseUrl) }
        .distinct()
        .sorted()
val manualForeignDirectRules = listOf("DOMAIN-KEYWORD,epicgames-download")
val directForeignRules = (foreignCategoryRules + manualForeignDirectRules).distinct().sorted()
check(proxyDomainRules.size >= 50) { "v2fly PROXY содержит только ${proxyDomainRules.size} правил" }
check(knownOpenaiRegexSkipped <= 1) { "v2fly openai повторяет неподдерживаемый regexp" }
check(knownEpicRegexSkipped <= 1) { "v2fly epicgames повторяет неподдерживаемый regexp" }
check(directDomainRules.size >= 500) { "v2fly DIRECT содержит только ${directDomainRules.size} правил" }
check(directForeignRules.size >= 1_000) { "v2fly зарубежный DIRECT содержит только ${directForeignRules.size} правил" }
check(proxyDomainRules.all { it.startsWith("DOMAIN") }) { "В PROXY обнаружено не доменное правило" }
check(directDomainRules.all { it.startsWith("DOMAIN") }) { "В DIRECT обнаружено не доменное правило" }
check(directForeignRules.all { it.startsWith("DOMAIN") }) { "В зарубежном DIRECT обнаружено не доменное правило" }
fun oneLabelSuffixes(rules: List<String>): Set<String> =
    rules
        .filter { it.startsWith("DOMAIN-SUFFIX,") }
        .map { it.substringAfter(',') }
        .filter { '.' !in it }
        .toSet()

check(oneLabelSuffixes(proxyDomainRules) == setOf("youtube")) {
    "В PROXY изменились правила для целых доменных зон"
}
val expectedRuOneLabelSuffixes =
    setOf(
        "moscow", "ru", "su", "tatar", "xn--80adxhks", "xn--80asehdb",
        "xn--80aswg", "xn--c1avg", "xn--d1acj3b", "xn--p1acf", "xn--p1ai", "yandex"
    )
check(oneLabelSuffixes(directDomainRules) == expectedRuOneLabelSuffixes) {
    "В российском DIRECT изменились правила для целых доменных зон"
}
val expectedForeignOneLabelSuffixes =
    setOf("apple", "azure", "bing", "hotmail", "microsoft", "office", "skype", "windows", "xbox")
check(oneLabelSuffixes(directForeignRules) == expectedForeignOneLabelSuffixes) {
    "В зарубежном DIRECT изменились правила для целых доменных зон"
}
check(proxyDomainRules.filter { it.startsWith("DOMAIN-KEYWORD,") } == manualProxyRules) {
    "В PROXY появились непроверенные широкие keyword-правила"
}
check(directDomainRules.none { it.startsWith("DOMAIN-KEYWORD,") }) {
    "В российском DIRECT появились непроверенные широкие keyword-правила"
}
check(directForeignRules.filter { it.startsWith("DOMAIN-KEYWORD,") } == manualForeignDirectRules) {
    "В зарубежном DIRECT появились непроверенные широкие keyword-правила"
}
fun proxyRuleOverlapsPriority(rule: String, priority: String): Boolean {
    val type = rule.substringBefore(',')
    val value = rule.substringAfter(',')
    return when (type) {
        "DOMAIN" -> value == priority || value.endsWith(".$priority")
        "DOMAIN-SUFFIX" ->
            value == priority || value.endsWith(".$priority") || priority.endsWith(".$value")
        "DOMAIN-KEYWORD" -> value in priority
        else -> error("Неизвестное PROXY-правило: $rule")
    }
}

priorityDomains.forEach { priority ->
    check(proxyDomainRules.none { rule -> proxyRuleOverlapsPriority(rule, priority) }) {
        "Приоритетный DIRECT-домен $priority перекрыт v2fly PROXY"
    }
}

val reFilterSources =
    listOf("domains_all.lst", "community.lst").associateWith { name ->
        normalizedLines(download("$reFilterBaseUrl/$name"))
            .map { domain ->
                val validated = validateDomain(domain, name)
                require('.' in validated) { "Re-filter содержит слишком широкое правило: $validated" }
                validated
            }
    }
reFilterSources.forEach { (name, domains) ->
    validateSourceCount(name, domains.size, previousCounts)
    generatedValidationFiles[Path.of("build/$name")] = domains.joinToString("\n", postfix = "\n")
}
val reFilterDomains = reFilterSources.values.flatten().distinct()
check(reFilterDomains.size >= 50_000) {
    "Re-filter содержит только ${reFilterDomains.size} уникальных доменов"
}
val nationalSuffixes = listOf("ru", "xn--p1ai", "su", "by")
fun isNationalDomain(domain: String): Boolean = nationalSuffixes.any { domain.endsWith(".$it") }

check(reFilterDomains.none { candidate ->
    priorityDomains.any { priority -> priority.endsWith(".$candidate") }
}) {
    "Re-filter содержит родительскую зону приоритетного DIRECT-правила"
}
val communityDomains = checkNotNull(reFilterSources["community.lst"])
val nationalCommunityCount = communityDomains.count(::isNationalDomain)
check(nationalCommunityCount <= 100) {
    "Re-filter community содержит неожиданно много национальных доменов: $nationalCommunityCount"
}
val broadNationalCount = checkNotNull(reFilterSources["domains_all.lst"]).count(::isNationalDomain)
val broadForeignDomains = checkNotNull(reFilterSources["domains_all.lst"]).filterNot(::isNationalDomain)
val communityProxyRules = communityDomains.distinct().map { domain -> "DOMAIN-SUFFIX,$domain" }.sorted()
val broadProxyRules = broadForeignDomains.distinct().map { domain -> "DOMAIN-SUFFIX,$domain" }.sorted()
val filteredReFilterRules =
    (communityDomains + broadForeignDomains)
        .distinct()
        .filterNot { domain ->
            priorityDomains.any { priority -> domain == priority || domain.endsWith(".$priority") }
        }
        .map { domain -> "DOMAIN-SUFFIX,$domain" }

val russianRanges =
    normalizedLines(download(ruGeoipUrl))
        .map { range ->
            cidrRule(range, "RU GeoIP")
            range
        }
        .distinct()
check(russianRanges.size >= 15_000) {
    "RU GeoIP содержит только ${russianRanges.size} диапазонов"
}
validateSourceCount("ru_geoip_ranges", russianRanges.size, previousCounts)
val privateRanges =
    listOf(
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10"
    )
val directIpRules =
    (privateRanges + russianRanges)
        .map { range -> cidrRule(range, "DIRECT_IP") }
        .distinct()
        .sorted()

fun generatedRuleFile(
    path: Path,
    rules: List<String>,
    sourceCommit: String
): String {
    if (samePolicyVersion) {
        validateGeneratedRuleCount(path, rules)
    }
    return buildString {
        appendLine("# Сгенерировано из проверенного источника")
        appendLine("# Source commit: $sourceCommit")
        rules.forEach { rule -> appendLine(rule) }
    }
}

generatedFiles[rulesDirectory.resolve("PROXY_DOMAIN.list")] =
    generatedRuleFile(rulesDirectory.resolve("PROXY_DOMAIN.list"), proxyDomainRules, v2flyCommit)
generatedFiles[rulesDirectory.resolve("PROXY_REFILTER_COMMUNITY.list")] =
    generatedRuleFile(rulesDirectory.resolve("PROXY_REFILTER_COMMUNITY.list"), communityProxyRules, reFilterCommit)
generatedFiles[rulesDirectory.resolve("PROXY_REFILTER_DOMAIN.list")] =
    generatedRuleFile(rulesDirectory.resolve("PROXY_REFILTER_DOMAIN.list"), broadProxyRules, reFilterCommit)
generatedFiles[rulesDirectory.resolve("DIRECT_DOMAIN.list")] =
    generatedRuleFile(rulesDirectory.resolve("DIRECT_DOMAIN.list"), directDomainRules, v2flyCommit)
generatedFiles[rulesDirectory.resolve("DIRECT_FOREIGN_DOMAIN.list")] =
    generatedRuleFile(rulesDirectory.resolve("DIRECT_FOREIGN_DOMAIN.list"), directForeignRules, v2flyCommit)
generatedFiles[rulesDirectory.resolve("DIRECT_IP.list")] =
    generatedRuleFile(rulesDirectory.resolve("DIRECT_IP.list"), directIpRules, ruGeoipCommit)


val templatePath = Path.of("shadowrocket.template.conf")
val shadowrocketConfig = Files.readString(templatePath)
check("{{" !in shadowrocketConfig) { "В Shadowrocket-конфиге остался незаменённый маркер" }
check("hydraponique/" !in shadowrocketConfig && "zeklop/" !in shadowrocketConfig) {
    "Shadowrocket-конфиг всё ещё зависит от старого источника"
}
val configLines = normalizedLines(shadowrocketConfig)
val expectedRuleOrder =
    listOf(
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/PROXY_DOMAIN.list,PROXY",
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/DIRECT_PRIORITY_DOMAIN.list,DIRECT",
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/PROXY_REFILTER_COMMUNITY.list,PROXY",
        "DOMAIN-SUFFIX,ru,DIRECT",
        "DOMAIN-SUFFIX,by,DIRECT",
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/PROXY_REFILTER_DOMAIN.list,PROXY",
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/DIRECT_DOMAIN.list,DIRECT",
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/DIRECT_FOREIGN_DOMAIN.list,DIRECT",
        "RULE-SET,https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/" +
            "main/rules/DIRECT_IP.list,DIRECT",
        "GEOIP,RU,DIRECT",
        "FINAL,PROXY"
    )
val positions = expectedRuleOrder.map { rule -> configLines.indexOf(rule) }
check(positions.all { it >= 0 } && positions.zipWithNext().all { (first, second) -> first < second }) {
    "Нарушен порядок DOMAIN/IP-правил Shadowrocket"
}
check("dns-direct-fallback-proxy = false" in configLines) {
    "DIRECT DNS не должен переключаться на proxy fallback"
}
check("private-ip-answer = true" in configLines) {
    "Private DNS-ответы должны приниматься"
}
generatedFiles[Path.of("shadowrocket.conf")] = shadowrocketConfig

val ipCheckProxyDomains =
    listOf(
        "2ip.ru",
        "2ip.io",
        "checkip.amazonaws.com",
        "ifconfig.me",
        "ip.sb",
        "ipapi.is",
        "ipify.org",
        "iplocate.io",
        "showip.net"
    )
val happProxyRules = (proxyDomainRules + filteredReFilterRules).distinct()
val happDirectRules =
    (directDomainRules + directForeignRules + priorityDomains.map { domain -> "DOMAIN-SUFFIX,$domain" }).distinct()
val happGeosite =
    geositeEntry("ROUTING-PROXY", happProxyRules) +
        geositeEntry("ROUTING-DIRECT", happDirectRules)
val happGeoip =
    geoipEntry("PRIVATE", privateRanges) +
        geoipEntry("RU", russianRanges)
check(geoCategoryNames(happGeosite) == setOf("ROUTING-PROXY", "ROUTING-DIRECT")) {
    "В Happ geosite.dat отсутствует нужная категория"
}
check(geoCategoryNames(happGeoip) == setOf("PRIVATE", "RU")) {
    "В Happ geoip.dat отсутствует нужная категория"
}

fun jsonStrings(values: List<String>): JsonArrayValue =
    JsonArrayValue(values.map(::JsonStringValue))

val happFields =
    linkedMapOf<String, JsonValue>(
        "Name" to JsonStringValue("Independent RU Routing"),
        "GlobalProxy" to JsonStringValue("true"),
        "UseChunkFiles" to JsonStringValue("true"),
        "RemoteDns" to JsonStringValue("8.8.8.8"),
        "DomesticDns" to JsonStringValue("77.88.8.8"),
        "RemoteDNSType" to JsonStringValue("DoH"),
        "RemoteDNSDomain" to JsonStringValue("https://8.8.8.8/dns-query"),
        "RemoteDNSIP" to JsonStringValue("8.8.8.8"),
        "DomesticDNSType" to JsonStringValue("DoH"),
        "DomesticDNSDomain" to JsonStringValue("https://77.88.8.8/dns-query"),
        "DomesticDNSIP" to JsonStringValue("77.88.8.8"),
        "Geoipurl" to JsonStringValue(
            "https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/main/happ/geoip.dat"
        ),
        "Geositeurl" to JsonStringValue(
            "https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/main/happ/geosite.dat"
        ),
        "DnsHosts" to JsonObjectValue(emptyMap()),
        "RouteOrder" to JsonStringValue("block-proxy-direct"),
        "DirectSites" to jsonStrings(
            listOf("geosite:routing-direct", "domain:ru", "domain:xn--p1ai", "domain:su", "domain:by")
        ),
        "DirectIp" to jsonStrings(listOf("geoip:private", "geoip:ru")),
        "ProxySites" to jsonStrings(
            listOf("geosite:routing-proxy") + ipCheckProxyDomains.map { domain -> "domain:$domain" }
        ),
        "ProxyIp" to jsonStrings(emptyList()),
        "BlockSites" to jsonStrings(emptyList()),
        "BlockIp" to jsonStrings(emptyList()),
        "DomainStrategy" to JsonStringValue("IPIfNonMatch"),
        "FakeDNS" to JsonStringValue("true")
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
    previousHapp?.values?.filterKeys { key -> key != "LastUpdated" } != happFields ||
        !Files.isRegularFile(Path.of("happ/geosite.dat")) ||
        !Files.readAllBytes(Path.of("happ/geosite.dat")).contentEquals(happGeosite) ||
        !Files.isRegularFile(Path.of("happ/geoip.dat")) ||
        !Files.readAllBytes(Path.of("happ/geoip.dat")).contentEquals(happGeoip)
val happTimestamp =
    if (happDataChanged) {
        maxOf(previousHappTimestamp + 1, Instant.now().epochSecond)
    } else {
        previousHappTimestamp
    }
happFields["LastUpdated"] = JsonStringValue(happTimestamp.toString())
val happJson = "${renderJson(JsonObjectValue(happFields))}\n"
val happLink =
    "happ://routing/add/${Base64.getEncoder().encodeToString(happJson.toByteArray(Charsets.UTF_8))}\n"
generatedFiles[Path.of("happ/happ-routing.json")] = happJson
generatedFiles[Path.of("happ/happ-routing-link.txt")] = happLink
generatedBinaryFiles[Path.of("happ/geosite.dat")] = happGeosite
generatedBinaryFiles[Path.of("happ/geoip.dat")] = happGeoip

generatedFiles[manifestPath] =
    buildString {
        appendLine("# Снимки независимых источников маршрутизации")
        appendLine("source_profile=independent-v1")
        appendLine("v2fly_commit=$v2flyCommit")
        appendLine("v2fly_category_ru_updated_at=$v2flyDirectUpdatedAt")
        appendLine("v2fly_proxy_categories=${proxyCategories.joinToString(",")}")
        appendLine("v2fly_proxy_rules=${proxyCategoryRules.size}")
        appendLine("manual_proxy_rules=${manualProxyRules.size}")
        appendLine("proxy_rules_total=${proxyDomainRules.size}")
        appendLine("v2fly_direct_rules=${directDomainRules.size}")
        appendLine("v2fly_foreign_direct_categories=${directForeignCategories.joinToString(",")}")
        appendLine("v2fly_foreign_direct_rules=${foreignCategoryRules.size}")
        appendLine("manual_foreign_direct_rules=${manualForeignDirectRules.size}")
        appendLine("foreign_direct_rules_total=${directForeignRules.size}")
        appendLine("v2fly_tagged_rules_skipped=$taggedDomainRulesSkipped")
        appendLine("v2fly_openai_regex_skipped=$knownOpenaiRegexSkipped")
        appendLine("v2fly_epicgames_regex_skipped=$knownEpicRegexSkipped")
        appendLine("refilter_commit=$reFilterCommit")
        appendLine("refilter_domains_updated_at=$reFilterUpdatedAt")
        appendLine("refilter_broad_national_excluded=$broadNationalCount")
        appendLine("refilter_community_national_kept=$nationalCommunityCount")
        appendLine("refilter_broad_foreign_rules=${broadProxyRules.size}")
        appendLine("refilter_community_rules=${communityProxyRules.size}")
        appendLine("refilter_proxy_rules=${filteredReFilterRules.size}")
        appendLine("ru_geoip_commit=$ruGeoipCommit")
        appendLine("ru_geoip_updated_at=$ruGeoipUpdatedAt")
        appendLine("ru_geoip_ranges=${russianRanges.size}")
        reFilterSources.forEach { (name, domains) -> appendLine("$name=${domains.size}") }
    }

Files.createDirectories(rulesDirectory)
Files.createDirectories(Path.of("happ"))
Files.createDirectories(Path.of("build"))
generatedFiles.forEach { (path, content) -> Files.writeString(path, content) }
generatedBinaryFiles.forEach { (path, content) -> Files.write(path, content) }
generatedValidationFiles.forEach { (path, content) -> Files.writeString(path, content) }
listOf("BLOCK_DOMAIN.list", "BLOCK_IP.list", "PROXY_IP.list").forEach { name ->
    Files.deleteIfExists(rulesDirectory.resolve(name))
}
println("PROXY_DOMAIN.list: ${proxyDomainRules.size} правил")
println("DIRECT_DOMAIN.list: ${directDomainRules.size} правил")
println("DIRECT_FOREIGN_DOMAIN.list: ${directForeignRules.size} правил")
println("DIRECT_IP.list: ${directIpRules.size} правил")
println("Re-filter: ${reFilterDomains.size} доменов")
println("v2fly: пропущено $taggedDomainRulesSkipped строк с атрибутами")
