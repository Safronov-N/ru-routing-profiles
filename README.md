# Shadowrocket RoscomVPN Routing

Автообновляемая адаптация профиля RoscomVPN для Shadowrocket.

Репозиторий преобразует категории из `HAPP/DEFAULT.JSON` в нативные списки правил Shadowrocket и публикует готовый конфиг без VPN-серверов, ключей и учётных данных.

Основная цель — максимально сохранить логику RoscomVPN, включая `DomainStrategy=IPIfNonMatch`, при использовании Shadowrocket.

## Установка

Импортируйте в Shadowrocket:

```text
https://raw.githubusercontent.com/Safronov-N/shadowrocket-roscomvpn-routing/main/shadowrocket.conf
```

Выберите своё VPN-подключение, примените конфиг и оставьте режим маршрутизации **Config**.

Для автоматического обновления включите фоновое обновление конфигурации в Shadowrocket и Background App Refresh в настройках iOS.

Конфиг использует текущий выбранный VPN-сервер: действие `PROXY` не содержит адресов серверов, ключей или других секретов.

## Профиль для Happ

[`happ/happ-routing.json`](happ/happ-routing.json) и [`happ/happ-routing-link.txt`](happ/happ-routing-link.txt) содержат профиль Happ. Его `geosite.dat` и `geoip.dat` находятся в [`happ/`](happ/). Перед импортом файлы `happ/` нужно опубликовать в ветке `main`: профиль ссылается на их URL в этом репозитории. Локальная ссылка импорта до публикации geo-файлов не заработает.

После публикации откройте ссылку из `happ/happ-routing-link.txt` на устройстве с Happ, выберите профиль **Shadowrocket-like Happ** для нужной подписки и переподключите VPN. Фрагментацию включите отдельно в настройках подключения Happ: профиль маршрутизации её не настраивает.

Профиль использует категории RoscomVPN и переносит дополнительные правила Shadowrocket: рекламный `REJECT.list` → `geosite:shadowrocket-reject`, домены Re-filter → `geosite:shadowrocket-proxy`, IP-списки Re-filter → `geoip:shadowrocket-proxy`, закреплённый `DIRECT_IP.list` → `geoip:shadowrocket-direct`, российские IP → `geoip:ru`, национальные зоны `.ru/.рф/.su/.by` → `DIRECT`, сервисы проверки внешнего IP → `PROXY`. Гео-файлы объединяются генератором каждые 6 часов вместе с Shadowrocket-конфигом.

Это перенос **маршрутизации**. DNS/fallback и `always-real-ip` Shadowrocket не имеют прямого соответствия в Happ JSON-профиле; профиль оставляет DNS-настройки RoscomVPN. Российская GeoIP-база взята из проекта Loyalsoldier, поэтому отдельные IP-решения могут отличаться от GeoLite2 Shadowrocket. Обновление локально импортированного профиля в Happ может потребовать повторного импорта; приложение не загружает geo-файлы чаще одного раза в неделю.

Happ применяет смену профиля после переподключения. Если подписка содержит готовую Xray JSON-конфигурацию, Happ не разрешает вручную добавлять к ней профиль маршрутизации; его должен предоставить источник подписки.

## Маршрутизация

Правила разделены на две основные фазы:

1. DOMAIN — маршрутизация по доменному имени.
2. IP — fallback по реальному IP, если ни одно доменное правило не совпало.

Это повторяет основную логику `DomainStrategy=IPIfNonMatch`.

### DOMAIN phase

Порядок:

1. `BlockSites` RoscomVPN → `REJECT`
2. дополнительный рекламный `REJECT.list` → `REJECT`
3. сервисы проверки внешнего IP → `PROXY`
4. `ProxySites` RoscomVPN → `PROXY`
5. доменные списки Re-filter → `PROXY`
6. `DirectSites` RoscomVPN → `DIRECT`
7. национальные зоны `.ru`, `.рф`, `.su`, `.by` → `DIRECT`

Если домен совпал на этом этапе, дальнейшая IP-проверка для него не требуется.

Например, если `rutube.ru` находится в `DirectSites`, он получает `DIRECT`, даже если один из его IP-адресов присутствует в стороннем IP-списке блокировок.

### IP phase

Если ни одно DOMAIN-правило не совпало, Shadowrocket разрешает hostname в реальный IP и продолжает проверку по IP-правилам.

Порядок:

1. `BlockIp` RoscomVPN → `REJECT`, если категория присутствует
2. `ProxyIp` RoscomVPN → `PROXY`, если категория присутствует
3. IP-списки Re-filter → `PROXY`
4. закреплённый `DIRECT_IP.list` → `DIRECT`
5. `GEOIP,RU` → `DIRECT`
6. всё остальное → `PROXY`

IP-правила этой фазы намеренно генерируются **без `no-resolve`**, чтобы они могли участвовать в IP fallback после промаха DOMAIN-фазы.

### Национальные зоны

Дополнительные правила:

```text
DOMAIN-SUFFIX,ru,DIRECT
DOMAIN-SUFFIX,xn--p1ai,DIRECT
DOMAIN-SUFFIX,su,DIRECT
DOMAIN-SUFFIX,by,DIRECT
```

являются политикой этого профиля поверх RoscomVPN.

Это означает, что обычный `.ru`, `.рф`, `.su` или `.by` домен, который не был ранее явно отправлен в `REJECT` или `PROXY`, идёт напрямую и не доходит до IP fallback.

## Генерируемые ruleset'ы

Генератор создаёт отдельные файлы для DOMAIN и IP правил:

```text
rules/BLOCK_DOMAIN.list
rules/PROXY_DOMAIN.list
rules/DIRECT_DOMAIN.list
```

`rules/DIRECT_IP.list` закреплён на проверенной версии Shadowrocket и не перезаписывается при автоматической генерации. 25 октября 2026 года upstream сократил `DirectIp` более чем на 30%; автоматический перенос такого изменения мог изменить работу российских сервисов. Happ использует этот же сохранённый список в категории `geoip:shadowrocket-direct`.

Дополнительно, если соответствующие категории присутствуют в актуальном `HAPP/DEFAULT.JSON`, создаются:

```text
rules/BLOCK_IP.list
rules/PROXY_IP.list
```

Если `BlockIp` или `ProxyIp` в upstream пусты, соответствующий файл не создаётся и `RULE-SET` не добавляется в `shadowrocket.conf`.

Старые объединённые:

```text
BLOCK.list
PROXY.list
DIRECT.list
```

больше не используются.

## Локальные и private-сети

До основной DOMAIN-фазы расположены ранние правила:

```text
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
```

`no-resolve` здесь используется намеренно: эти правила предназначены для соединений, где IP уже известен, и не должны вызывать преждевременный DNS-resolve до DOMAIN-фазы.

Private IP-категории RoscomVPN также входят в `DIRECT_IP.list` и участвуют в полноценной IP-фазе уже без `no-resolve`.

## Автообновление

GitHub Actions каждые 6 часов:

1. Загружает актуальный `HAPP/DEFAULT.JSON`.
2. Проверяет ожидаемые:
   - `GlobalProxy=true`
   - `RouteOrder=block-proxy-direct`
   - `DomainStrategy=IPIfNonMatch`
3. Получает закреплённые версии geosite и geoip из URL самого RoscomVPN-профиля.
4. Генерирует DOMAIN ruleset'ы и доступные IP ruleset'ы, сохраняя закреплённый `DIRECT_IP.list`.
5. Не создаёт `BLOCK_IP` / `PROXY_IP`, если соответствующие upstream-категории пусты.
6. Переносит `DnsHosts` в секцию `[Host]`.
7. Преобразует совместимую часть `geosite:whitelist` в `always-real-ip`.
8. Проверяет структуру доменов, CIDR, порядок DOMAIN/IP-фаз и DNS-защиту.
9. Проверяет, что дополнительный `REJECT.list`, расположенный в DOMAIN-фазе, содержит только доменные правила.
10. Создаёт профиль Happ и объединённые geo-файлы, затем публикует изменения только после успешной генерации и проверок.

Если upstream меняется несовместимо или отдаёт некорректные данные, сборка завершается ошибкой, а последняя рабочая опубликованная версия остаётся доступной.

## DNS, Fake-IP и whitelist

Основной DNS:

```text
tls://common.dot.dns.yandex.net
```

Fallback DNS:

```text
https://dns.google/dns-query#proxy
https://cloudflare-dns.com/dns-query#proxy
system
```

Для DIRECT DNS отключён переход на proxy fallback:

```text
dns-direct-fallback-proxy = false
```

Также включено:

```text
private-ip-answer = true
```

чтобы Shadowrocket принимал private DNS-ответы для локальных сетей и параллельных VPN.

Обычные домены могут использовать Fake-IP.

Совместимые домены из `geosite:whitelist`, а также необходимые записи `DnsHosts`, автоматически добавляются в:

```text
always-real-ip
```

Глобальный:

```text
always-real-ip = *
```

намеренно не используется.

Домены сервисов проверки внешнего IP исключаются из `always-real-ip`, поскольку они принудительно маршрутизируются через `PROXY`.

## Проверка внешнего IP

Следующие сервисы всегда отправляются через VPN:

```text
2ip.ru
checkip.amazonaws.com
ifconfig.me
ip.sb
ipapi.is
ipify.org
iplocate.io
showip.net
```

Это позволяет использовать их для проверки фактического внешнего адреса прокси независимо от остальных DIRECT-правил.

## GeoLite2

Для более свежей Country-базы можно указать в:

**Settings → GeoLite2 Database → Country URL**

```text
https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb
```

Поле ASN можно оставить пустым.

Без внешнего URL Shadowrocket использует встроенную GeoLite2 Country-базу.

`GEOIP,RU,DIRECT` расположен в конце IP-фазы и служит дополнительным DIRECT fallback после RoscomVPN и Re-filter IP-правил.

## Ограничения

- Обобщённое regexp для односегментных private-hostname из `geosite:private` нельзя точно выразить используемыми правилами Shadowrocket, поэтому такое regexp пропускается.
- Полные private FQDN и private IP-маршруты продолжают работать.
- Re-filter загружается Shadowrocket напрямую из ветки `main`, поэтому изменения этих списков не проходят через генератор репозитория.
- Дополнительный рекламный `REJECT.list` также загружается из внешнего репозитория, но генератор проверяет, что его текущий формат остаётся совместим с DOMAIN-фазой.
- Национальные `.ru/.рф/.su/.by` правила являются дополнительной политикой данного профиля, а не прямым преобразованием отдельной категории RoscomVPN.
- Scoped DNS только выбирает DNS-сервер; маршрут и сетевой доступ должны быть настроены отдельно.

## Разработка

Запуск генератора:

```bash
kotlinc -script scripts/generate.main.kts
```

Автоматически создаваемые:

```text
rules/*.list
shadowrocket.conf
happ/*
```

не редактируются вручную, кроме отдельного пересмотра закреплённого `rules/DIRECT_IP.list`.

Pull request проверяется повторной генерацией.

GitHub Actions также проверяет, что после запуска генератора committed-файлы совпадают с результатом генерации:

```bash
git diff --exit-code -- rules shadowrocket.conf happ
```

## Источники и лицензии

- [RoscomVPN routing](https://github.com/hydraponique/roscomvpn-routing)
- [RoscomVPN geosite](https://github.com/hydraponique/roscomvpn-geosite)
- [RoscomVPN geoip](https://github.com/hydraponique/roscomvpn-geoip)
- [Re-filter](https://github.com/1andrevich/Re-filter-lists)

Уведомления о лицензиях сторонних данных находятся в [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).
