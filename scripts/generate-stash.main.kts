#!/usr/bin/env kotlin

import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

data class StashProvider(
    val name: String,
    val fileName: String,
    val behavior: String,
    val payload: List<String>,
    val inlineRules: List<String>
)

fun activeLines(path: Path): List<String> =
    Files
        .readAllLines(path)
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith('#') }

fun yamlQuote(value: String): String = "'${value.replace("'", "''")}'"

fun stashPolicy(policy: String): String =
    when (policy) {
        "PROXY" -> "RU-PROXY"
        "DIRECT" -> "DIRECT"
        else -> error("Неподдерживаемая политика: $policy")
    }

fun validateDomain(value: String) {
    check(value.length in 1..253 && value == value.lowercase(Locale.ROOT)) {
        "Некорректное имя домена: $value"
    }
    check(value.split('.').all { label ->
        label.length in 1..63 && !label.startsWith('-') && !label.endsWith('-') &&
            label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
    }) { "Некорректная метка домена: $value" }
}

fun validateCidr(type: String, value: String) {
    val parts = value.split('/')
    check(parts.size == 2) { "Некорректный CIDR: $value" }
    val prefix = parts[1].toIntOrNull() ?: error("Некорректный префикс CIDR: $value")
    val address = parts[0]
    when (type) {
        "IP-CIDR" -> {
            val octets = address.split('.')
            check(prefix in 0..32 && octets.size == 4 && octets.all { octet ->
                octet.isNotEmpty() && octet.all { it in '0'..'9' } &&
                    (octet == "0" || !octet.startsWith('0')) &&
                    octet.toIntOrNull()?.let { it in 0..255 } == true
            }) { "Некорректный IPv4 CIDR: $value" }
        }
        "IP-CIDR6" -> {
            check(prefix in 0..128 && ':' in address && address.all {
                it in '0'..'9' || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.'
            }) { "Некорректный IPv6 CIDR: $value" }
            check(InetAddress.getByName(address) is Inet6Address) { "Некорректный IPv6 CIDR: $value" }
        }
        else -> error("Неизвестный тип IP-правила: $type")
    }
}

fun validateSpecialRule(type: String, value: String) {
    check(value.isNotBlank() && value.none { it.isWhitespace() || it.isISOControl() || it == ',' }) {
        "Некорректное правило $type: $value"
    }
    if (type == "DOMAIN-WILDCARD") {
        check(value.all { it in 'a'..'z' || it in '0'..'9' || it in ".-_*?" }) {
            "Неподдерживаемый wildcard: $value"
        }
    }
}

val expectedListNames =
    setOf(
        "PROXY_DOMAIN.list",
        "DIRECT_PRIORITY_DOMAIN.list",
        "PROXY_REFILTER_COMMUNITY.list",
        "PROXY_REFILTER_DOMAIN.list",
        "DIRECT_DOMAIN.list",
        "DIRECT_FOREIGN_DOMAIN.list",
        "DIRECT_IP.list"
    )
val repositoryBaseUrl = "https://raw.githubusercontent.com/Safronov-N/ru-routing-profiles/main"
val outputDirectory = Path.of("stash")
val providers = linkedMapOf<String, StashProvider>()
val stashRules = mutableListOf<String>()

fun loadProvider(url: String): StashProvider {
    val uri = URI.create(url)
    val listName = uri.path.substringAfterLast('/')
    check(listName in expectedListNames && url == "$repositoryBaseUrl/rules/$listName") {
        "Неизвестный источник RULE-SET: $url"
    }
    val sourcePath = Path.of("rules", listName)
    val sourceRules = activeLines(sourcePath)
    check(sourceRules.isNotEmpty()) { "Пустой список $sourcePath" }
    val payload = mutableListOf<String>()
    val inlineRules = mutableListOf<String>()
    val behavior = if (listName == "DIRECT_IP.list") "ipcidr" else "domain"
    sourceRules.forEach { rule ->
        val parts = rule.split(',')
        check(parts.size == 2) { "В $sourcePath ожидалось правило без политики: $rule" }
        val (type, value) = parts
        when (type) {
            "DOMAIN", "DOMAIN-SUFFIX" -> {
                check(behavior == "domain") { "Доменное правило в IP-списке: $rule" }
                validateDomain(value)
                payload.add(if (type == "DOMAIN-SUFFIX") "+.$value" else value)
            }
            "DOMAIN-WILDCARD", "DOMAIN-KEYWORD" -> {
                check(behavior == "domain") { "Доменное правило в IP-списке: $rule" }
                validateSpecialRule(type, value)
                inlineRules.add(rule)
            }
            "IP-CIDR", "IP-CIDR6" -> {
                check(behavior == "ipcidr") { "IP-правило в доменном списке: $rule" }
                validateCidr(type, value)
                payload.add(value)
            }
            else -> error("Неподдерживаемое правило в $sourcePath: $rule")
        }
    }
    check(payload.isNotEmpty()) { "Пустой payload $sourcePath" }
    check(payload.size + inlineRules.size == sourceRules.size) { "Потеря правил $sourcePath" }
    check(payload.distinct().size == payload.size && inlineRules.distinct().size == inlineRules.size) {
        "Повторные правила в $sourcePath"
    }
    val slug =
        listName
            .removeSuffix(".list")
            .lowercase(Locale.ROOT)
            .replace('_', '-')
    return StashProvider("ru-$slug", "$slug.yaml", behavior, payload, inlineRules)
}

var section = ""
var ruleSectionCount = 0
activeLines(Path.of("shadowrocket.conf")).forEach { line ->
    if (line.startsWith('[')) {
        check(line.endsWith(']')) { "Некорректная секция Shadowrocket: $line" }
        section = line
        if (section == "[Rule]") ruleSectionCount++
    } else if (section == "[Rule]") {
        check(stashRules.none { it.startsWith("MATCH,") }) { "Правило после FINAL: $line" }
        val parts = line.split(',')
        val type = parts.first()
        when (type) {
            "RULE-SET" -> {
                check(parts.size == 3) { "Некорректный RULE-SET: $line" }
                val provider = loadProvider(parts[1])
                check(providers.put(provider.name, provider) == null) {
                    "Повторная ссылка на RULE-SET: ${provider.name}"
                }
                val policy = stashPolicy(parts[2])
                // Внутри одного исходного списка все правила имеют одинаковую политику.
                provider.inlineRules.forEach { rule -> stashRules.add("$rule,$policy") }
                stashRules.add("RULE-SET,${provider.name},$policy")
            }
            "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD" -> {
                check(parts.size == 3) { "Некорректное доменное правило: $line" }
                if (type in setOf("DOMAIN", "DOMAIN-SUFFIX")) {
                    validateDomain(parts[1])
                } else {
                    validateSpecialRule(type, parts[1])
                }
                stashRules.add("$type,${parts[1]},${stashPolicy(parts[2])}")
            }
            "IP-CIDR", "IP-CIDR6" -> {
                check(parts.size in 3..4 && (parts.size == 3 || parts[3] == "no-resolve")) {
                    "Некорректное IP-правило: $line"
                }
                validateCidr(type, parts[1])
                val suffix = if (parts.size == 4) ",no-resolve" else ""
                stashRules.add("$type,${parts[1]},${stashPolicy(parts[2])}$suffix")
            }
            "GEOIP" -> {
                check(parts.size == 3 && parts[1] == "RU" && parts[2] == "DIRECT") {
                    "Неизвестное GEOIP-правило: $line"
                }
                stashRules.add(line)
            }
            "FINAL" -> {
                check(parts.size == 2) { "Некорректный FINAL: $line" }
                stashRules.add("MATCH,${stashPolicy(parts[1])}")
            }
            else -> error("Неподдерживаемое правило Shadowrocket: $line")
        }
    }
}
check(ruleSectionCount == 1 && stashRules.lastOrNull() == "MATCH,RU-PROXY") {
    "Ожидалась одна секция [Rule], завершающаяся FINAL,PROXY"
}
check(providers.size == expectedListNames.size) { "Подключены не все ожидаемые списки: ${providers.keys}" }

val privateIpv6Ranges = listOf("::1/128", "fc00::/7", "fe80::/10")
val directIpProvider = checkNotNull(providers["ru-direct-ip"])
check(privateIpv6Ranges.all { it in directIpProvider.payload }) {
    "В DIRECT_IP отсутствуют ожидаемые локальные IPv6-сети"
}
val privateIpv6Rules = privateIpv6Ranges.map { range -> "IP-CIDR6,$range,DIRECT,no-resolve" }
val firstDomainIndex = stashRules.indexOfFirst { it.startsWith("DOMAIN") || it.startsWith("RULE-SET,") }
check(firstDomainIndex >= 0) { "Не найдена доменная фаза Stash" }
// Stash может обслуживать IPv6 независимо от ipv6=false в исходном Shadowrocket-профиле.
stashRules.addAll(firstDomainIndex, privateIpv6Rules.filterNot { it in stashRules })

val generatedFiles = linkedMapOf<Path, String>()
providers.values.forEach { provider ->
    generatedFiles[outputDirectory.resolve("rules").resolve(provider.fileName)] =
        buildString {
            appendLine("# Сгенерировано scripts/generate-stash.main.kts; не редактировать вручную.")
            appendLine("payload:")
            provider.payload.forEach { entry -> appendLine("  - ${yamlQuote(entry)}") }
        }
}
fun renderOverride(): String =
    buildString {
        appendLine("# Сгенерировано из shadowrocket.conf и rules/*.list; не редактировать вручную.")
        appendLine("name: 'Independent RU Routing'")
        appendLine("desc: 'Маршрутизация для РФ. Выберите свой VPN-сервер в группе RU-PROXY.'")
        appendLine("mode: rule")
        appendLine()
        appendLine("# Группа использует серверы и провайдеров действующей подписки.")
        appendLine("# До подключения выберите рабочий сервер; пустая подписка не поддерживается.")
        appendLine("proxy-groups:")
        appendLine("  - name: RU-PROXY")
        appendLine("    type: select")
        appendLine("    include-all: true")
        appendLine()
        appendLine("rule-providers:")
        providers.values.forEach { provider ->
            appendLine("  ${provider.name}:")
            appendLine("    type: http")
            appendLine("    behavior: ${provider.behavior}")
            appendLine("    format: yaml")
            appendLine("    url: $repositoryBaseUrl/stash/rules/${provider.fileName}")
            appendLine("    path: ./rule-providers/${provider.name}.yaml")
            appendLine("    interval: 21600")
        }
        appendLine()
        appendLine("# Замена исключает перехват трафика прежними правилами подписки.")
        appendLine("rules: #!replace")
        stashRules.forEach { rule -> appendLine("  - ${yamlQuote(rule)}") }
    }
val stashOverride = renderOverride()
generatedFiles[outputDirectory.resolve("routing.stoverride")] = stashOverride
// Сохраняем прежний адрес автообновления уже установленных дополнений Stash.
generatedFiles[Path.of("rules/Independent-RU-Routing.stoverride")] = stashOverride

// Пишем результаты только после проверки всех входных списков и правил.
Files.createDirectories(outputDirectory.resolve("rules"))
generatedFiles.forEach { (path, content) -> Files.writeString(path, content) }
println("Stash: ${providers.size} providers, ${stashRules.size} правил, ${generatedFiles.size} файлов")
println("Stash: ${providers.values.sumOf { it.payload.size }} записей в domain/ipcidr payload")
