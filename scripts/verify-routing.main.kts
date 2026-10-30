#!/usr/bin/env kotlin

import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale

data class IcannPublicSuffixes(
    val version: String,
    val sourceSha256: String,
    val exactRules: Set<String>,
    val wildcardBases: Set<String>,
    val exceptions: Set<String>
) {
    fun contains(domain: String): Boolean {
        val normalized =
            if (domain.all { it.code < 128 }) {
                domain.lowercase(Locale.ROOT)
            } else {
                IDN.toASCII(domain, IDN.ALLOW_UNASSIGNED).lowercase(Locale.ROOT)
            }
        if (normalized in exceptions) return false
        // База wildcard тоже охватывает всю административную область, а не отдельный сервис.
        return normalized in exactRules || normalized in wildcardBases ||
            normalized.substringAfter('.', "") in wildcardBases
    }
}

fun parseIcannPublicSuffixes(source: String): IcannPublicSuffixes {
    val lines =
        source
            .lineSequence()
            .map { it.trim() }
            .toList()
    val begin = "// ===BEGIN ICANN DOMAINS==="
    val end = "// ===END ICANN DOMAINS==="
    val privateBegin = "// ===BEGIN PRIVATE DOMAINS==="
    val privateEnd = "// ===END PRIVATE DOMAINS==="
    listOf(begin, end, privateBegin, privateEnd).forEach { marker ->
        check(lines.count { it == marker } == 1) { "PSL: ожидался ровно один маркер $marker" }
    }
    val start = lines.indexOf(begin)
    val finish = lines.indexOf(end)
    check(start < finish && finish < lines.indexOf(privateBegin) &&
        lines.indexOf(privateBegin) < lines.indexOf(privateEnd)) {
        "PSL: нарушен порядок разделов ICANN/PRIVATE"
    }
    val version =
        lines.singleOrNull { it.startsWith("// VERSION: ") }?.removePrefix("// VERSION: ")
            ?: error("PSL: отсутствует единственная версия снимка")
    check(Regex("\\d{4}-\\d{2}-\\d{2}_\\d{2}-\\d{2}-\\d{2}_UTC").matches(version)) {
        "PSL: некорректная версия $version"
    }
    val exactRules = mutableSetOf<String>()
    val wildcardBases = mutableSetOf<String>()
    val exceptions = mutableSetOf<String>()
    lines
        .subList(start + 1, finish)
        .filter { it.isNotEmpty() && !it.startsWith("//") }
        .forEach { rule ->
            val value =
                when {
                    rule.startsWith("!") -> rule.removePrefix("!")
                    rule.startsWith("*.") -> rule.removePrefix("*.")
                    else -> rule
                }
            check(value.isNotEmpty() && value.none { it.isWhitespace() || it in "!*" }) {
                "PSL: некорректное правило $rule"
            }
            val domain =
                IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES or IDN.ALLOW_UNASSIGNED).lowercase(Locale.ROOT)
            check(domain.length in 1..253 && domain.split('.').all { label ->
                label.length in 1..63 && !label.startsWith('-') && !label.endsWith('-')
            }) { "PSL: некорректный домен $rule" }
            val target =
                when {
                    rule.startsWith("!") -> exceptions
                    rule.startsWith("*.") -> wildcardBases
                    else -> exactRules
                }
            check(target.add(domain)) { "PSL: повторное правило $rule" }
        }
    check(exactRules.isNotEmpty()) { "PSL: пустой раздел ICANN" }
    check(exceptions.all { it.substringAfter('.', "") in wildcardBases }) {
        "PSL: исключение не имеет родительского wildcard-правила"
    }
    val hash =
        MessageDigest
            .getInstance("SHA-256")
            .digest(source.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }
    return IcannPublicSuffixes(version, hash, exactRules, wildcardBases, exceptions)
}

fun loadIcannPublicSuffixes(path: Path): IcannPublicSuffixes {
    val bytes = Files.readAllBytes(path)
    val source = String(bytes, Charsets.UTF_8)
    check(source.toByteArray(Charsets.UTF_8).contentEquals(bytes)) { "PSL: некорректный UTF-8" }
    return parseIcannPublicSuffixes(source).also { suffixes ->
        check(suffixes.exactRules.size >= 5_000 && suffixes.wildcardBases.isNotEmpty() &&
            suffixes.exceptions.isNotEmpty()) {
            "PSL: снимок ICANN неожиданно мал или неполон"
        }
    }
}

sealed interface HappJsonValue

data class HappJsonText(val value: String) : HappJsonValue

data class HappJsonArray(val values: List<HappJsonValue>) : HappJsonValue

data class HappJsonObject(val values: Map<String, HappJsonValue>) : HappJsonValue

class HappJsonParser(private val source: String) {
    private var position = 0

    fun parse(): HappJsonObject {
        val result = parseValue() as? HappJsonObject ?: error("Корень Happ JSON — не объект")
        skipWhitespace()
        check(position == source.length) { "Лишние данные после Happ JSON" }
        return result
    }

    private fun parseValue(): HappJsonValue {
        skipWhitespace()
        check(position < source.length) { "Неожиданный конец Happ JSON" }
        return when (source[position]) {
            '"' -> HappJsonText(parseString())
            '[' -> parseArray()
            '{' -> parseObject()
            else -> error("Неподдерживаемое значение Happ JSON в позиции $position")
        }
    }

    private fun parseObject(): HappJsonObject {
        expect('{')
        skipWhitespace()
        val values = linkedMapOf<String, HappJsonValue>()
        if (consume('}')) return HappJsonObject(values)
        while (true) {
            val key = parseString()
            expect(':')
            check(values.put(key, parseValue()) == null) { "Повторный ключ Happ JSON: $key" }
            skipWhitespace()
            if (consume('}')) return HappJsonObject(values)
            expect(',')
        }
    }

    private fun parseArray(): HappJsonArray {
        expect('[')
        skipWhitespace()
        val values = mutableListOf<HappJsonValue>()
        if (consume(']')) return HappJsonArray(values)
        while (true) {
            values.add(parseValue())
            skipWhitespace()
            if (consume(']')) return HappJsonArray(values)
            expect(',')
        }
    }

    private fun parseString(): String {
        expect('"')
        return buildString {
            while (position < source.length) {
                val character = source[position++]
                when (character) {
                    '"' -> return@buildString
                    '\\' -> {
                        check(position < source.length) { "Незавершённое экранирование JSON" }
                        when (val escaped = source[position++]) {
                            '"', '\\', '/' -> append(escaped)
                            'b' -> append('\b')
                            'f' -> append('\u000c')
                            'n' -> append('\n')
                            'r' -> append('\r')
                            't' -> append('\t')
                            'u' -> {
                                check(position + 4 <= source.length) { "Незавершённый Unicode Happ JSON" }
                                val code = source.substring(position, position + 4).toIntOrNull(16)
                                    ?: error("Некорректный Unicode Happ JSON")
                                append(code.toChar())
                                position += 4
                            }
                            else -> error("Некорректное экранирование Happ JSON: $escaped")
                        }
                    }
                    else -> {
                        check(character.code >= 0x20) { "Управляющий символ Happ JSON" }
                        append(character)
                    }
                }
            }
            error("Строка Happ JSON не закрыта")
        }
    }

    private fun expect(character: Char) {
        skipWhitespace()
        check(position < source.length && source[position] == character) {
            "Ожидался '$character' в Happ JSON, позиция $position"
        }
        position++
    }

    private fun consume(character: Char): Boolean {
        skipWhitespace()
        if (position >= source.length || source[position] != character) return false
        position++
        return true
    }

    private fun skipWhitespace() {
        while (position < source.length && source[position] in " \t\r\n") position++
    }
}

fun HappJsonObject.text(key: String): String =
    (values[key] as? HappJsonText)?.value ?: error("Нет строкового поля Happ $key")

fun HappJsonObject.textArray(key: String): List<String> =
    (values[key] as? HappJsonArray)?.values?.map { value ->
        (value as? HappJsonText)?.value ?: error("В массиве $key ожидается строка")
    } ?: error("В Happ JSON отсутствует массив $key")

fun HappJsonObject.textObject(key: String): Map<String, String> =
    (values[key] as? HappJsonObject)?.values?.mapValues { (name, value) ->
        (value as? HappJsonText)?.value ?: error("Поле $key.$name — не строка")
    } ?: error("В Happ JSON отсутствует объект $key")

data class ProtoField(val number: Int, val integer: Int? = null, val bytes: ByteArray? = null)

class ProtoReader(private val source: ByteArray) {
    private var position = 0

    fun next(): ProtoField? {
        if (position == source.size) return null
        val tag = readVarint()
        val number = tag ushr 3
        check(number > 0) { "Нулевое поле protobuf" }
        return when (tag and 7) {
            0 -> ProtoField(number, integer = readVarint())
            2 -> {
                val length = readVarint()
                check(length >= 0 && length <= source.size - position) { "Длина protobuf неверна" }
                val data = source.copyOfRange(position, position + length)
                position += length
                ProtoField(number, bytes = data)
            }
            else -> error("Неподдерживаемый тип protobuf-поля: ${tag and 7}")
        }
    }

    private fun readVarint(): Int {
        var result = 0
        repeat(5) { index ->
            check(position < source.size) { "Оборванный protobuf varint" }
            val byte = source[position++].toInt() and 0xff
            check(index < 4 || byte < 16) { "Переполнение protobuf varint" }
            result = result or ((byte and 0x7f) shl (7 * index))
            if (byte < 0x80) return result
        }
        error("Слишком длинный protobuf varint")
    }
}

fun ProtoField.requiredBytes(): ByteArray = bytes ?: error("Поле $number — не байты")

fun ProtoField.requiredInt(): Int = integer ?: error("Поле $number должно содержать число")

fun ProtoField.requiredText(): String {
    val raw = requiredBytes()
    val value = String(raw, Charsets.UTF_8)
    check(value.toByteArray(Charsets.UTF_8).contentEquals(raw)) { "Некорректный UTF-8 в protobuf" }
    return value
}

fun decodeHappDomain(bytes: ByteArray, category: String): Rule {
    val reader = ProtoReader(bytes)
    var type: Int? = null
    var value: String? = null
    while (true) {
        val field = reader.next() ?: break
        when (field.number) {
            1 -> {
                check(type == null) { "Повторный тип домена в $category" }
                type = field.requiredInt()
            }
            2 -> {
                check(value == null) { "Повторное значение домена в $category" }
                value = field.requiredText()
            }
            else -> error("Неизвестное поле домена Happ: ${field.number}")
        }
    }
    val domainType =
        when (type) {
            0 -> "DOMAIN-KEYWORD"
            2 -> "DOMAIN-SUFFIX"
            3 -> "DOMAIN"
            else -> error("Неподдерживаемый тип домена Happ: $type")
        }
    val domain = checkNotNull(value) { "Домен Happ без значения в $category" }
    check(domain.isNotBlank() && domain == domain.trim()) { "Некорректный домен Happ: $domain" }
    val policy = if (category == "ROUTING-PROXY") "PROXY" else "DIRECT"
    return Rule(
        domainType,
        domain.lowercase(),
        policy,
        "happ/geosite.dat:$category",
        encodedValue = domain
    )
}

fun decodeHappGeosite(path: Path): Map<String, List<Rule>> {
    val result = linkedMapOf<String, List<Rule>>()
    val reader = ProtoReader(Files.readAllBytes(path))
    while (true) {
        val entry = reader.next() ?: break
        check(entry.number == 1) { "Неизвестное поле Happ geosite.dat: ${entry.number}" }
        val categoryReader = ProtoReader(entry.requiredBytes())
        var category: String? = null
        val encodedRules = mutableListOf<ByteArray>()
        while (true) {
            val field = categoryReader.next() ?: break
            when (field.number) {
                1 -> {
                    check(category == null) { "Повторное имя категории Happ geosite.dat" }
                    category = field.requiredText()
                }
                2 -> encodedRules.add(field.requiredBytes())
                else -> error("Неизвестное поле категории Happ geosite.dat: ${field.number}")
            }
        }
        val name = checkNotNull(category) { "Категория Happ geosite.dat без имени" }
        check(name in setOf("ROUTING-PROXY", "ROUTING-DIRECT") && !result.containsKey(name)) {
            "Неожиданная или повторная категория Happ geosite.dat: $name"
        }
        val rules = encodedRules.map { bytes -> decodeHappDomain(bytes, name) }
        check(rules.isNotEmpty()) { "Пустая категория Happ geosite.dat: $name" }
        result[name] = rules
    }
    check(result.keys == setOf("ROUTING-PROXY", "ROUTING-DIRECT")) {
        "Категории Happ geosite.dat: ${result.keys}"
    }
    return result
}

data class HappCidr(val address: ByteArray, val prefix: Int)

fun decodeHappCidr(bytes: ByteArray, category: String): HappCidr {
    val reader = ProtoReader(bytes)
    var address: ByteArray? = null
    var prefix: Int? = null
    while (true) {
        val field = reader.next() ?: break
        when (field.number) {
            1 -> {
                check(address == null) { "Повторный адрес Happ CIDR в $category" }
                address = field.requiredBytes()
            }
            2 -> {
                check(prefix == null) { "Повторная маска Happ CIDR в $category" }
                prefix = field.requiredInt()
            }
            else -> error("Неизвестное поле Happ CIDR: ${field.number}")
        }
    }
    val addressBytes = checkNotNull(address) { "Happ CIDR без адреса в $category" }
    val bits = checkNotNull(prefix) { "Happ CIDR без маски в $category" }
    check(addressBytes.size in setOf(4, 16) && bits in 0..(addressBytes.size * 8)) {
        "Некорректный Happ CIDR в $category"
    }
    return HappCidr(addressBytes, bits)
}

fun decodeHappGeoip(path: Path): Map<String, List<HappCidr>> {
    val result = linkedMapOf<String, List<HappCidr>>()
    val reader = ProtoReader(Files.readAllBytes(path))
    while (true) {
        val entry = reader.next() ?: break
        check(entry.number == 1) { "Неизвестное поле Happ geoip.dat: ${entry.number}" }
        val categoryReader = ProtoReader(entry.requiredBytes())
        var category: String? = null
        val encodedRanges = mutableListOf<ByteArray>()
        while (true) {
            val field = categoryReader.next() ?: break
            when (field.number) {
                1 -> {
                    check(category == null) { "Повторное имя категории Happ geoip.dat" }
                    category = field.requiredText()
                }
                2 -> encodedRanges.add(field.requiredBytes())
                else -> error("Неизвестное поле категории Happ geoip.dat: ${field.number}")
            }
        }
        val name = checkNotNull(category) { "Категория Happ geoip.dat без имени" }
        check(name in setOf("PRIVATE", "RU") && !result.containsKey(name)) {
            "Неожиданная или повторная категория Happ geoip.dat: $name"
        }
        val ranges = encodedRanges.map { bytes -> decodeHappCidr(bytes, name) }
        check(ranges.isNotEmpty()) { "Пустая категория Happ geoip.dat: $name" }
        result[name] = ranges
    }
    check(result.keys == setOf("PRIVATE", "RU")) { "Категории Happ geoip.dat: ${result.keys}" }
    return result
}

fun matchesHappCidr(cidr: HappCidr, target: ByteArray): Boolean {
    if (cidr.address.size != target.size) return false
    val fullBytes = cidr.prefix / 8
    for (index in 0 until fullBytes) {
        if (cidr.address[index] != target[index]) return false
    }
    val remainingBits = cidr.prefix % 8
    if (remainingBits == 0) return true
    val mask = (0xff shl (8 - remainingBits)) and 0xff
    return (cidr.address[fullBytes].toInt() and mask) == (target[fullBytes].toInt() and mask)
}

data class Rule(
    val type: String,
    val value: String,
    val policy: String,
    val source: String,
    val noResolve: Boolean = false,
    val encodedValue: String = value
)

fun activeLines(path: Path): List<String> =
    Files.readAllLines(path)
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }

fun verifyDomainRuleCoverage(before: List<String>, after: List<String>, context: String) {
    check(before.isNotEmpty() && after.isNotEmpty()) { "$context: пустой набор доменных правил" }
    val original = before.distinct()
    original.forEach { line ->
        val parts = line.split(',')
        check(parts.size == 2 && parts[0] in setOf("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD") &&
            parts[1].isNotBlank()) {
            "$context: неизвестное исходное доменное правило: $line"
        }
    }
    val retained = after.toSet()
    check(retained.size == after.size) { "$context: после минимизации появились дубликаты" }

    // Подпоследовательность запрещает добавление правил, замену типа и перестановку приоритетов.
    var position = 0
    after.forEach { line ->
        while (position < original.size && original[position] != line) position++
        check(position < original.size) { "$context: новое или переставленное правило: $line" }
        position++
    }
    val suffixes =
        after
            .filter { it.startsWith("DOMAIN-SUFFIX,") }
            .map { it.substringAfter(',') }
            .toSet()
    original.filterNot { it in retained }.forEach { line ->
        val type = line.substringBefore(',')
        check(type in setOf("DOMAIN", "DOMAIN-SUFFIX")) {
            "$context: удалено правило без доказуемого DOMAIN-SUFFIX покрытия: $line"
        }
        var ancestor = line.substringAfter(',')
        while (ancestor !in suffixes && '.' in ancestor) ancestor = ancestor.substringAfter('.')
        check(ancestor in suffixes) { "$context: удалено непокрытое правило: $line" }
    }
}

fun originalDomainRules(name: String): List<String> = activeLines(Path.of("build", "domain-rules", name))

fun verifyDomainCoverageFixtures() {
    verifyDomainRuleCoverage(
        listOf(
            "DOMAIN,exact.example",
            "DOMAIN,api.example.com",
            "DOMAIN-SUFFIX,deep.api.example.com",
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN-SUFFIX,other.test",
            "DOMAIN-KEYWORD,token"
        ),
        listOf(
            "DOMAIN,exact.example",
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN-SUFFIX,other.test",
            "DOMAIN-KEYWORD,token"
        ),
        "Положительный контроль покрытия"
    )
    verifyDomainRuleCoverage(
        listOf("DOMAIN,host.xn--p1ai", "DOMAIN-SUFFIX,xn--p1ai"),
        listOf("DOMAIN-SUFFIX,xn--p1ai"),
        "Контроль IDN-зоны"
    )
    listOf(0 to "ToKeN", 3 to "MiXeD.Example").forEach { (type, value) ->
        val bytes = byteArrayOf(8, type.toByte(), 18, value.length.toByte()) + value.toByteArray(Charsets.UTF_8)
        val decoded = decodeHappDomain(bytes, "ROUTING-PROXY")
        check(decoded.value == value.lowercase() && decoded.encodedValue == value) {
            "При декодировании потеряно исходное написание доменного правила"
        }
        val original = listOf("${decoded.type},$value")
        verifyDomainRuleCoverage(
            original,
            listOf("${decoded.type},${decoded.encodedValue}"),
            "Контроль исходного регистра Happ"
        )
        check(runCatching {
            verifyDomainRuleCoverage(original, listOf("${decoded.type},${decoded.value}"), "Контроль смены регистра")
        }.isFailure) {
            "Проверка минимизации не обнаружила изменение регистра доменного правила"
        }
    }
    val invalidChanges =
        listOf(
            listOf("DOMAIN,example.com") to listOf("DOMAIN-SUFFIX,example.com"),
            listOf("DOMAIN-SUFFIX,example.com", "DOMAIN-SUFFIX,api.example.com") to
                listOf("DOMAIN-SUFFIX,api.example.com"),
            listOf("DOMAIN-SUFFIX,example.com", "DOMAIN,badexample.com") to
                listOf("DOMAIN-SUFFIX,example.com"),
            listOf("DOMAIN-SUFFIX,a.example.com", "DOMAIN-SUFFIX,b.example.com") to
                listOf("DOMAIN-SUFFIX,a.example.com"),
            listOf("DOMAIN-KEYWORD,token", "DOMAIN-SUFFIX,example.com") to
                listOf("DOMAIN-SUFFIX,example.com"),
            listOf("DOMAIN,example.com", "DOMAIN-SUFFIX,api.example.com") to listOf("DOMAIN,example.com"),
            listOf("DOMAIN,token.example", "DOMAIN-KEYWORD,token") to listOf("DOMAIN-KEYWORD,token"),
            listOf("DOMAIN-SUFFIX,example.com") to
                listOf("DOMAIN-SUFFIX,example.com", "DOMAIN-SUFFIX,example.com"),
            listOf("DOMAIN-SUFFIX,a.example", "DOMAIN-SUFFIX,b.example") to
                listOf("DOMAIN-SUFFIX,b.example", "DOMAIN-SUFFIX,a.example"),
            listOf("DOMAIN-SUFFIX,example.com") to emptyList()
        )
    invalidChanges.forEachIndexed { index, (before, after) ->
        check(runCatching { verifyDomainRuleCoverage(before, after, "Отрицательный контроль $index") }.isFailure) {
            "Принято изменение покрытия или порядка доменных правил: $index"
        }
    }
}

val referencedLocalLists = mutableListOf<String>()

fun checkedRulesPath(url: String): Path {
    val uri = URI.create(url)
    check(
        uri.scheme == "https" &&
            uri.host == "raw.githubusercontent.com" &&
            uri.query == null &&
            uri.fragment == null
    ) {
        "RULE-SET должен ссылаться на raw.githubusercontent.com: $url"
    }
    val segments = uri.path.trimStart('/').split('/')
    check(
        segments.size == 5 && segments[0] == "Safronov-N" &&
            segments[1] == "ru-routing-profiles" &&
            segments[2] == "main" && segments[3] == "rules"
    ) {
        "Некорректный путь собственного списка: $url"
    }
    val rulePath = segments[4]
    check(rulePath.matches(Regex("[A-Za-z0-9._-]+"))) {
        "Некорректный путь списка: $url"
    }
    referencedLocalLists.add(rulePath)
    return Path.of("rules", rulePath).also { path ->
        check(Files.isRegularFile(path)) {
            "Опубликованное правило не найдено локально: $path"
        }
    }
}

fun parseInlineRule(line: String, source: String): Rule {
    val parts = line.split(',')
    val type = parts.first()
    return when (type) {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD" -> {
            check(parts.size == 3 && parts[1].isNotBlank() && parts[2] in setOf("PROXY", "DIRECT")) {
                "Некорректное доменное правило $source: $line"
            }
            Rule(type, parts[1].lowercase(), parts[2], source)
        }
        "IP-CIDR", "IP-CIDR6" -> {
            check(parts.size in 3..4 && parts[1].isNotBlank() && parts[2] in setOf("PROXY", "DIRECT")) {
                "Некорректное IP-правило $source: $line"
            }
            check(parts.size == 3 || parts[3] == "no-resolve") {
                "Некорректный флаг IP-правила $source: $line"
            }
            validateCidr(type, parts[1], source)
            Rule(type, parts[1], parts[2], source, parts.size == 4)
        }
        "GEOIP" -> {
            check(parts.size in 3..4 && parts[1] == "RU" && parts[2] == "DIRECT") {
                "Некорректное GEOIP-правило $source: $line"
            }
            check(parts.size == 3 || parts[3] == "no-resolve") {
                "Некорректный флаг GEOIP-правила $source: $line"
            }
            Rule(type, parts[1], parts[2], source, parts.size == 4 && parts[3] == "no-resolve")
        }
        "FINAL" -> {
            check(parts.size == 2 && parts[1] in setOf("PROXY", "DIRECT")) {
                "Некорректное финальное правило $source: $line"
            }
            Rule(type, "", parts[1], source)
        }
        else -> error("Неподдерживаемое правило $source: $line")
    }
}

fun expandRuleSet(url: String, policy: String): List<Rule> {
    val path = checkedRulesPath(url)
    val expectedPolicy =
        when (path.fileName.toString()) {
            "PROXY_DOMAIN.list", "PROXY_REFILTER_COMMUNITY.list", "PROXY_REFILTER_DOMAIN.list" -> "PROXY"
            "DIRECT_PRIORITY_DOMAIN.list", "DIRECT_DOMAIN.list", "DIRECT_FOREIGN_DOMAIN.list",
            "DIRECT_IP.list" -> "DIRECT"
            else -> error("Неожиданный RULE-SET: $path")
        }
    check(policy == expectedPolicy) { "$path: ожидалось $expectedPolicy, получено $policy" }
    val lines = activeLines(path)
    check(lines.isNotEmpty()) { "Список $path не содержит правил" }
    return lines.map { line ->
        val parts = line.split(',')
        check(
            parts.size == 2 && parts[0] in setOf(
                "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6"
            )
        ) {
            "Некорректное правило в $path: $line"
        }
        parseInlineRule("$line,$policy", path.toString())
    }
}

fun loadRules(): List<Rule> {
    val configPath = Path.of("shadowrocket.conf")
    val config = Files.readAllLines(configPath)
    val skipProxy = config.firstOrNull { it.trim().startsWith("skip-proxy = ") }
        ?: error("В shadowrocket.conf отсутствует skip-proxy")
    check(skipProxy.split('=').last().split(',').map { it.trim() }.contains("localhost")) {
        "localhost отсутствует в skip-proxy"
    }
    val ruleSection = config.indexOfFirst { it.trim() == "[Rule]" }
    check(ruleSection >= 0) { "В shadowrocket.conf отсутствует секция [Rule]" }
    val rules = mutableListOf<Rule>()
    config.drop(ruleSection + 1).forEachIndexed { index, sourceLine ->
        val line = sourceLine.trim()
        if (line.isEmpty() || line.startsWith("#")) {
            return@forEachIndexed
        }
        check(!line.startsWith("[")) { "Неожиданная секция после [Rule]: $line" }
        val parts = line.split(',')
        val source = "shadowrocket.conf:${ruleSection + index + 2}"
        when (parts.first()) {
            "RULE-SET" -> {
                check(parts.size == 3) { "Некорректный RULE-SET $source: $line" }
                rules.addAll(expandRuleSet(parts[1], parts[2]))
            }
            else -> rules.add(parseInlineRule(line, source))
        }
    }
    check(rules.isNotEmpty()) { "В shadowrocket.conf нет правил" }
    return rules
}

fun wildcardMatches(pattern: String, domain: String): Boolean {
    val regex = buildString {
        append('^')
        pattern.forEach { character ->
            when (character) {
                '*' -> append(".*")
                '?' -> append('.')
                else -> append(Regex.escape(character.toString()))
            }
        }
        append('$')
    }
    return Regex(regex).matches(domain)
}

fun matchesDomain(rule: Rule, domain: String): Boolean =
    when (rule.type) {
        "DOMAIN" -> domain == rule.value
        "DOMAIN-SUFFIX" -> domain == rule.value || domain.endsWith(".${rule.value}")
        "DOMAIN-KEYWORD" -> rule.value in domain
        "DOMAIN-WILDCARD" -> wildcardMatches(rule.value, domain)
        "FINAL" -> true
        else -> false
    }

fun ipv4Value(address: String): Long? {
    val octets = address.split('.')
    if (octets.size != 4 || octets.any { it.isEmpty() || it.any { character -> !character.isDigit() } }) {
        return null
    }
    val values = octets.map { it.toIntOrNull() ?: return null }
    if (values.any { it !in 0..255 }) {
        return null
    }
    return values.fold(0L) { result, value -> (result shl 8) or value.toLong() }
}

fun validateCidr(type: String, cidr: String, source: String) {
    val parts = cidr.split('/')
    check(parts.size == 2) { "Некорректный CIDR в $source: $cidr" }
    val prefix = parts[1].toIntOrNull() ?: error("Некорректная маска CIDR в $source: $cidr")
    when (type) {
        "IP-CIDR" -> check(ipv4Value(parts[0]) != null && prefix in 0..32) {
            "Некорректный IPv4 CIDR в $source: $cidr"
        }
        "IP-CIDR6" -> check(
            ':' in parts[0] && '%' !in parts[0] &&
                runCatching { InetAddress.getByName(parts[0]) is Inet6Address }.getOrDefault(false) &&
                prefix in 0..128
        ) {
            "Некорректный IPv6 CIDR в $source: $cidr"
        }
    }
}

fun matchesIpv4Cidr(cidr: String, address: Long): Boolean {
    val parts = cidr.split('/')
    check(parts.size == 2) { "Некорректный CIDR: $cidr" }
    val network = ipv4Value(parts[0]) ?: error("Некорректный IPv4 CIDR: $cidr")
    val prefix = parts[1].toIntOrNull() ?: error("Некорректный IPv4 prefix: $cidr")
    check(prefix in 0..32) { "Некорректный IPv4 prefix: $cidr" }
    val mask = if (prefix == 0) 0L else (0xffffffffL shl (32 - prefix)) and 0xffffffffL
    return (address and mask) == (network and mask)
}

fun matchedRule(rules: List<Rule>, target: String): Rule {
    val domain = target.lowercase()
    val address = ipv4Value(target)
    return rules.firstOrNull { rule ->
        if (address == null) {
            matchesDomain(rule, domain)
        } else {
            when (rule.type) {
                "IP-CIDR" -> matchesIpv4Cidr(rule.value, address)
                "FINAL" -> true
                else -> false
            }
        }
    } ?: error("Для $target не найдено правило маршрутизации")
}

verifyDomainCoverageFixtures()

val rules = loadRules()
val firstDomainIndex = rules.indexOfFirst { it.type.startsWith("DOMAIN") }
val lastDomainIndex = rules.indexOfLast { it.type.startsWith("DOMAIN") }
val firstResolvingIpIndex = rules.indexOfFirst {
    it.type in setOf("IP-CIDR", "IP-CIDR6", "GEOIP") && !it.noResolve
}
check(firstDomainIndex >= 0 && firstResolvingIpIndex > lastDomainIndex) {
    "IP-проверка начинается раньше завершения DOMAIN-фазы"
}
check(rules.last().type == "FINAL" && rules.last().policy == "PROXY") {
    "Ожидался FINAL,PROXY последним правилом"
}
check(rules.count { it.type == "FINAL" } == 1) {
    "В конфигурации должно быть ровно одно правило FINAL"
}
val expectedLocalLists =
    listOf(
        "PROXY_DOMAIN.list",
        "DIRECT_PRIORITY_DOMAIN.list",
        "PROXY_REFILTER_COMMUNITY.list",
        "PROXY_REFILTER_DOMAIN.list",
        "DIRECT_DOMAIN.list",
        "DIRECT_FOREIGN_DOMAIN.list",
        "DIRECT_IP.list"
    )
check(referencedLocalLists == expectedLocalLists) {
    "Состав или порядок собственных списков изменился: $referencedLocalLists"
}
listOf("PROXY_DOMAIN.list", "DIRECT_DOMAIN.list", "DIRECT_FOREIGN_DOMAIN.list").forEach { name ->
    val original = originalDomainRules(name)
    val optimized = activeLines(Path.of("rules", name))
    verifyDomainRuleCoverage(original, optimized, name)
    println("$name: покрытие сохранено, ${original.size} → ${optimized.size} правил")
}
val firstOrderedSources =
    listOf(
        "rules/PROXY_DOMAIN.list",
        "rules/DIRECT_PRIORITY_DOMAIN.list",
        "rules/PROXY_REFILTER_COMMUNITY.list"
    )
val lastOrderedSources =
    listOf(
        "rules/PROXY_REFILTER_DOMAIN.list",
        "rules/DIRECT_DOMAIN.list",
        "rules/DIRECT_FOREIGN_DOMAIN.list",
        "rules/DIRECT_IP.list"
    )
val nationalZones = listOf("ru", "xn--p1ai", "su", "by")
val reFilterCommit =
    activeLines(Path.of("rules/SOURCE_MANIFEST.txt"))
        .single { it.startsWith("refilter_commit=") }
        .substringAfter('=')
check(reFilterCommit.matches(Regex("[0-9a-fA-F]{40}"))) {
    "Некорректный SHA Re-filter в SOURCE_MANIFEST.txt: $reFilterCommit"
}
fun verifyReFilterRuleSet(name: String, expected: List<String>) {
    val path = Path.of("rules", name)
    val header = Files.readAllLines(path).firstOrNull { it.startsWith("# Source commit: ") }
    check(header == "# Source commit: $reFilterCommit") {
        "$path: SHA источника не совпадает с SOURCE_MANIFEST.txt"
    }
    check(originalDomainRules(name) == expected) {
        "$path: исходные правила минимизации отличаются от проверенного входа Re-filter"
    }
    val optimized = activeLines(path)
    verifyDomainRuleCoverage(expected, optimized, path.toString())
    println("$path: покрытие Re-filter сохранено, ${expected.size} → ${optimized.size} правил")
}
val icannSuffixes = loadIcannPublicSuffixes(Path.of("data/public_suffix_list.dat"))
val publicSuffixFixture =
    """
    // VERSION: 2026-10-28_13-15-55_UTC
    // ===BEGIN ICANN DOMAINS===
    com
    com.cy
    *.ck
    !www.ck
    *.kawasaki.jp
    !city.kawasaki.jp
    公司.cn
    // ===END ICANN DOMAINS===
    // ===BEGIN PRIVATE DOMAINS===
    pages.dev
    // ===END PRIVATE DOMAINS===
    """.trimIndent()
val fixtureSuffixes = parseIcannPublicSuffixes(publicSuffixFixture)
listOf("com", "com.cy", "ck", "foo.ck", "kawasaki.jp", "foo.kawasaki.jp", "公司.cn", "xn--55qx5d.cn").forEach {
    check(fixtureSuffixes.contains(it)) { "Не распознана административная зона: $it" }
}
listOf("2gis.com.cy", "www.ck", "deep.foo.ck", "city.kawasaki.jp", "deep.city.kawasaki.jp", "pages.dev").forEach {
    check(!fixtureSuffixes.contains(it)) { "Домен сервиса ошибочно принят за административную зону: $it" }
}
listOf(
    publicSuffixFixture.replace("// ===BEGIN ICANN DOMAINS===", ""),
    publicSuffixFixture.replace("// ===END ICANN DOMAINS===", ""),
    publicSuffixFixture.replace("com\n", "bad..suffix\n"),
    publicSuffixFixture.replace("com\n", "// ===BEGIN ICANN DOMAINS===\ncom\n"),
    publicSuffixFixture.replace(Regex("(?m)^(?!//).+$"), "")
).forEach { malformed ->
    check(runCatching { parseIcannPublicSuffixes(malformed) }.isFailure) {
        "Повреждённый Public Suffix List принят без ошибки"
    }
}
listOf("com.cy", "gov.pl", "co.uk").forEach { suffix ->
    check(icannSuffixes.contains(suffix)) { "Нет контрольной административной зоны: $suffix" }
}
listOf("2gis.com.cy", "politis.com.cy", "example.co.uk", "pages.dev", "notion.site", "gitlab.io").forEach {
    check(!icannSuffixes.contains(it)) { "Конкретный сервис ошибочно исключён по Public Suffix List: $it" }
}
val rawCommunityDomains = activeLines(Path.of("build/community.lst")).toSet()
val rawBroadDomains = activeLines(Path.of("build/domains_all.lst"))
val excludedPublicSuffixes =
    (rawCommunityDomains + rawBroadDomains)
        .filter(icannSuffixes::contains)
        .distinct()
        .sorted()
val sourceManifest = activeLines(Path.of("rules/SOURCE_MANIFEST.txt")).associate { line ->
    line.substringBefore('=') to line.substringAfter('=')
}
check(sourceManifest["public_suffix_version"] == icannSuffixes.version &&
    sourceManifest["public_suffix_sha256"] == icannSuffixes.sourceSha256) {
    "Снимок Public Suffix List не совпадает с SOURCE_MANIFEST.txt"
}
check(sourceManifest["refilter_public_suffix_excluded"] == excludedPublicSuffixes.size.toString() &&
    sourceManifest["refilter_public_suffix_excluded_domains"] == excludedPublicSuffixes.joinToString(",")) {
    "Исключённые административные зоны не совпадают с SOURCE_MANIFEST.txt"
}
val communityDomains = rawCommunityDomains.filterNot(icannSuffixes::contains).toSet()
println("Re-filter: исключены административные зоны ${excludedPublicSuffixes.joinToString(", ")}")
verifyReFilterRuleSet(
    "PROXY_REFILTER_COMMUNITY.list",
    communityDomains.map { domain -> "DOMAIN-SUFFIX,$domain" }.sorted()
)
verifyReFilterRuleSet(
    "PROXY_REFILTER_DOMAIN.list",
    rawBroadDomains
        .filterNot { domain ->
            icannSuffixes.contains(domain) || nationalZones.any { zone -> domain.endsWith(".$zone") }
        }
        .distinct()
        .map { domain -> "DOMAIN-SUFFIX,$domain" }
        .sorted()
)
val nationalIndices = nationalZones.map { zone ->
    rules.indexOfFirst { rule ->
        rule.type == "DOMAIN-SUFFIX" && rule.value == zone && rule.policy == "DIRECT" &&
            rule.source.startsWith("shadowrocket.conf:")
    }
}
val orderedIndices =
    firstOrderedSources.map { source -> rules.indexOfFirst { it.source == source } } +
        nationalIndices +
        lastOrderedSources.map { source -> rules.indexOfFirst { it.source == source } }
check(orderedIndices.all { it >= 0 } && orderedIndices.zipWithNext().all { (first, second) -> first < second }) {
    "Нарушен порядок списков и национальных зон: $orderedIndices"
}
val precedingNationalRules = rules.take(nationalIndices.first())
val nationalCanary = activeLines(Path.of("build/domains_all.lst")).firstOrNull { candidate ->
    candidate.endsWith(".ru") &&
        communityDomains.none { domain -> candidate == domain || candidate.endsWith(".$domain") } &&
        precedingNationalRules.none { rule -> matchesDomain(rule, candidate) }
} ?: error("Нет .ru-canary из domains_all.lst")
val nationalCanaryRule = matchedRule(rules, nationalCanary)
check(nationalCanaryRule.type == "DOMAIN-SUFFIX" && nationalCanaryRule.value == "ru" &&
    nationalCanaryRule.policy == "DIRECT" && nationalCanaryRule.source.startsWith("shadowrocket.conf:")) {
    "$nationalCanary: национальная зона должна быть перед общим Re-filter RULE-SET"
}
println("$nationalCanary → DIRECT (национальная зона перед PROXY_REFILTER_DOMAIN.list)")

val foreignDirectCanaries =
    listOf(
        "apple.com",
        "microsoft.com",
        "epicgames.com",
        "riotgames.com",
        "escapefromtarkov.com",
        "store.steampowered.com",
        "steamcommunity.com",
        "twitch.tv",
        "pinterest.com",
        "faceit.com",
        "epicgames-download1.akamaized.net"
    )
val dynamicOpenaiCanary = "chatgpt-async-webps-prod-demo-123.webpubsub.azure.com"

// Псевдодомен проверяет FINAL без DNS и последующей IP-фазы.
val expectations =
    linkedMapOf(
        "youtube.com" to "PROXY",
        "youtube.ru" to "PROXY",
        "github.com" to "PROXY",
        "telegram.org" to "PROXY",
        "instagram.com" to "PROXY",
        "discord.com" to "PROXY",
        "openai.com" to "PROXY",
        "chatgpt.com" to "PROXY",
        dynamicOpenaiCanary to "PROXY",
        "4pda.ru" to "PROXY",
        "sub.4pda.ru" to "PROXY",
        "2ip.io" to "PROXY",
        "copilot.microsoft.com" to "PROXY",
        "gql.twitch.tv" to "PROXY",
        "ipify.org" to "PROXY",
        "gosuslugi.ru" to "DIRECT",
        "nalog.ru" to "DIRECT",
        "lkfl2.nalog.ru" to "DIRECT",
        "ozon.ru" to "DIRECT",
        "api.ozon.ru" to "DIRECT",
        "netmonet.co" to "DIRECT",
        "2gis.com.cy" to "DIRECT",
        "politis.com.cy" to "PROXY",
        "213.24.64.175" to "DIRECT",
        "10.1.2.3" to "DIRECT",
        "127.0.0.1" to "DIRECT",
        "unlisted-routing-check.example" to "PROXY"
    )
foreignDirectCanaries.forEach { domain -> expectations[domain] = "DIRECT" }
expectations.forEach { (target, expected) ->
    val actual = matchedRule(rules, target)
    if (ipv4Value(target) == null && target != "unlisted-routing-check.example") {
        check(actual.type != "FINAL") {
            "$target маршрутизирован по FINAL без явного доменного правила"
        }
    }
    if (target == "unlisted-routing-check.example") {
        check(actual.type == "FINAL") { "Неизвестный домен должен попадать в FINAL" }
    }
    check(actual.policy == expected) {
        "$target: ожидался $expected, получен ${actual.policy} " +
            "(${actual.source}, ${actual.type}, ${actual.value})"
    }
    if (target in setOf("openai.com", "chatgpt.com", dynamicOpenaiCanary)) {
        check(actual.source == "rules/PROXY_DOMAIN.list") {
            "$target должен быть явно задан в PROXY_DOMAIN.list"
        }
    }
    if (target in setOf("4pda.ru", "sub.4pda.ru", "copilot.microsoft.com", "gql.twitch.tv")) {
        check(actual.source == "rules/PROXY_REFILTER_COMMUNITY.list") {
            "$target должен идти через PROXY_REFILTER_COMMUNITY.list"
        }
    }
    if (target == "2ip.io") {
        check(actual.source.startsWith("shadowrocket.conf:")) {
            "$target должен быть задан явно в shadowrocket.conf"
        }
    }
    if (target in foreignDirectCanaries) {
        check(actual.source == "rules/DIRECT_FOREIGN_DOMAIN.list") {
            "$target должен идти через DIRECT_FOREIGN_DOMAIN.list"
        }
    }
    println("$target → $expected (${actual.source})")
}
println("Маршрутов: ${expectations.size}; DOMAIN/IP порядок сохранён")

fun happDomainRules(values: List<String>, category: String, policy: String): List<Rule> =
    values.drop(1).map { reference ->
        check(reference.startsWith("domain:")) { "Неизвестное правило Happ $category: $reference" }
        val domain = reference.removePrefix("domain:")
        check(domain.isNotBlank() && domain == domain.lowercase()) {
            "Некорректный домен Happ $category: $domain"
        }
        Rule("DOMAIN-SUFFIX", domain, policy, "happ/happ-routing.json:$category")
    }

fun verifyHapp() {
    val jsonPath = Path.of("happ/happ-routing.json")
    val jsonBytes = Files.readAllBytes(jsonPath)
    val jsonText = String(jsonBytes, Charsets.UTF_8)
    check(jsonText.toByteArray(Charsets.UTF_8).contentEquals(jsonBytes)) { "Happ JSON: плохой UTF-8" }
    val profile = HappJsonParser(jsonText).parse()
    val expectedFields =
        mapOf(
            "GlobalProxy" to "true",
            "UseChunkFiles" to "true",
            "DomainStrategy" to "IPIfNonMatch",
            "RouteOrder" to "block-proxy-direct",
            "RemoteDns" to "8.8.8.8",
            "DomesticDns" to "77.88.8.8",
            "RemoteDNSType" to "DoH",
            "RemoteDNSDomain" to "https://8.8.8.8/dns-query",
            "RemoteDNSIP" to "8.8.8.8",
            "DomesticDNSType" to "DoH",
            "DomesticDNSDomain" to "https://77.88.8.8/dns-query",
            "DomesticDNSIP" to "77.88.8.8",
            "FakeDNS" to "true",
            "Geoipurl" to
                "https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/main/happ/geoip.dat",
            "Geositeurl" to
                "https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/main/happ/geosite.dat"
        )
    expectedFields.forEach { (key, expected) ->
        val actual = profile.text(key)
        check(actual == expected) { "Happ $key: ожидалось $expected, получено $actual" }
    }
    check(profile.textObject("DnsHosts").isEmpty()) { "Happ DnsHosts должен быть пустым" }
    check(profile.text("LastUpdated").toLongOrNull()?.let { it > 0 } == true) {
        "Happ LastUpdated должен быть положительным числом"
    }

    val proxySites = profile.textArray("ProxySites")
    val directSites = profile.textArray("DirectSites")
    check(proxySites == listOf(
        "geosite:routing-proxy",
        "domain:2ip.ru",
        "domain:2ip.io",
        "domain:checkip.amazonaws.com",
        "domain:ifconfig.me",
        "domain:ip.sb",
        "domain:ipapi.is",
        "domain:ipify.org",
        "domain:iplocate.io",
        "domain:showip.net"
    )) { "Неожиданные ProxySites Happ: $proxySites" }
    check(directSites == listOf(
        "geosite:routing-direct",
        "domain:ru",
        "domain:xn--p1ai",
        "domain:su",
        "domain:by"
    )) { "Неожиданные DirectSites Happ: $directSites" }
    check(profile.textArray("DirectIp") == listOf("geoip:private", "geoip:ru")) {
        "Неожиданные DirectIp Happ"
    }
    listOf("ProxyIp", "BlockSites", "BlockIp").forEach { key ->
        check(profile.textArray(key).isEmpty()) { "Happ $key должен быть пустым" }
    }

    val link = Files.readString(Path.of("happ/happ-routing-link.txt"))
    val prefix = "happ://routing/add/"
    check(link.startsWith(prefix) && link.endsWith("\n")) { "Некорректный deeplink Happ" }
    val encoded = link.removePrefix(prefix).removeSuffix("\n")
    val decoded = Base64.getDecoder().decode(encoded)
    check(decoded.contentEquals(jsonBytes)) { "Deeplink Happ содержит другой JSON" }
    check(HappJsonParser(String(decoded, Charsets.UTF_8)).parse() == profile) {
        "Deeplink Happ содержит некорректный профиль"
    }

    val geosite = decodeHappGeosite(Path.of("happ/geosite.dat"))
    val geoip = decodeHappGeoip(Path.of("happ/geoip.dat"))
    geosite.forEach { (category, decoded) ->
        val original = originalDomainRules("$category.list")
        val optimized = decoded.map { rule -> "${rule.type},${rule.encodedValue}" }
        verifyDomainRuleCoverage(original, optimized, "Happ $category")
        println("Happ $category: покрытие сохранено, ${original.size} → ${optimized.size} правил")
    }
    check("4pda.ru" in communityDomains) { "4pda.ru отсутствует в community.lst" }
    val proxyRules = checkNotNull(geosite["ROUTING-PROXY"]) + happDomainRules(proxySites, "ProxySites", "PROXY")
    val directRules = checkNotNull(geosite["ROUTING-DIRECT"]) + happDomainRules(directSites, "DirectSites", "DIRECT")
    check(proxyRules.none { it.type == "DOMAIN-SUFFIX" && it.value in excludedPublicSuffixes }) {
        "Исключённая административная зона осталась в Happ geosite.dat"
    }
    check(proxyRules.size >= 50_000 && directRules.size >= 500) {
        "Мало доменов Happ: PROXY=${proxyRules.size}, DIRECT=${directRules.size}"
    }
    val privateRanges = checkNotNull(geoip["PRIVATE"])
    val russianRanges = checkNotNull(geoip["RU"])
    check(privateRanges.size >= 6 && russianRanges.size >= 15_000) {
        "Мало IP Happ: PRIVATE=${privateRanges.size}, RU=${russianRanges.size}"
    }

    val domainExpectations =
        linkedMapOf(
            "youtube.com" to "PROXY",
            "youtube.ru" to "PROXY",
            "github.com" to "PROXY",
            "telegram.org" to "PROXY",
            "instagram.com" to "PROXY",
            "discord.com" to "PROXY",
            "openai.com" to "PROXY",
            "chatgpt.com" to "PROXY",
            dynamicOpenaiCanary to "PROXY",
            "4pda.ru" to "PROXY",
            "sub.4pda.ru" to "PROXY",
            "2ip.io" to "PROXY",
            "copilot.microsoft.com" to "PROXY",
            "gql.twitch.tv" to "PROXY",
            "ipify.org" to "PROXY",
            "gosuslugi.ru" to "DIRECT",
            "nalog.ru" to "DIRECT",
            "lkfl2.nalog.ru" to "DIRECT",
            "ozon.ru" to "DIRECT",
            "api.ozon.ru" to "DIRECT",
            "netmonet.co" to "DIRECT",
            "2gis.com.cy" to "DIRECT",
            "politis.com.cy" to "PROXY",
            nationalCanary to "DIRECT"
        )
    foreignDirectCanaries.forEach { domain -> domainExpectations[domain] = "DIRECT" }
    domainExpectations.forEach { (domain, expected) ->
        val matched = proxyRules.firstOrNull { matchesDomain(it, domain) }
            ?: directRules.firstOrNull { matchesDomain(it, domain) }
            ?: error("Happ не содержит явного доменного правила для $domain")
        check(matched.policy == expected) {
            "Happ $domain: ожидалось $expected, получено ${matched.policy} (${matched.source})"
        }
        println("Happ $domain → $expected (${matched.source})")
    }

    val ipExpectations =
        linkedMapOf(
            "10.1.2.3" to "PRIVATE",
            "127.0.0.1" to "PRIVATE",
            "::1" to "PRIVATE",
            "213.24.64.175" to "RU"
        )
    ipExpectations.forEach { (address, category) ->
        val bytes = InetAddress.getByName(address).address
        val ranges = checkNotNull(geoip[category])
        check(ranges.any { cidr -> matchesHappCidr(cidr, bytes) }) {
            "Happ $address отсутствует в geoip:$category"
        }
        println("Happ $address → DIRECT (geoip:$category)")
    }
    val foreignIp = InetAddress.getByName("1.1.1.1").address
    check((privateRanges + russianRanges).none { cidr -> matchesHappCidr(cidr, foreignIp) }) {
        "Happ 1.1.1.1 ошибочно попал в DIRECT"
    }
    println("Happ 1.1.1.1 → PROXY (GlobalProxy)")
    println("Happ: доменов ${domainExpectations.size}, IP ${ipExpectations.size + 1}, deeplink JSON")
}

verifyHapp()
