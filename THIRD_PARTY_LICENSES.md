# Источники и условия использования данных

Генерируемые списки и geo-файлы содержат переработанные данные внешних проектов. Ниже указаны источники, их опубликованные лицензии и сделанные преобразования. Права на исходные данные сохраняются за авторами.

## Public Suffix List

[`data/public_suffix_list.dat`](data/public_suffix_list.dat) содержит неизменённый снимок [официального Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat). Исходные уведомления, версия и commit сохранены в самом файле. Список распространяется на условиях [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/).

Генератор использует только секцию ICANN для исключения административных зон из Re-filter; правила PRIVATE не используются. Содержимое PSL не добавляется в маршруты. Версия и SHA-256 защитного снимка записываются в `rules/SOURCE_MANIFEST.txt`.

## v2fly domain-list-community

[Исходные доменные категории](https://github.com/v2fly/domain-list-community) преобразуются в `rules/PROXY_DOMAIN.list`, `rules/DIRECT_DOMAIN.list`, `rules/DIRECT_FOREIGN_DOMAIN.list` и категории `ROUTING-PROXY` / `ROUTING-DIRECT` файла `happ/geosite.dat`. Используемый коммит записан в `rules/SOURCE_MANIFEST.txt`.

[MIT License](https://github.com/v2fly/domain-list-community/blob/master/LICENSE)

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Re-filter

Домены из [Re-filter-lists](https://github.com/1andrevich/Re-filter-lists) загружаются по закреплённому SHA. Для Shadowrocket они преобразуются в типизированные `rules/PROXY_REFILTER_COMMUNITY.list` и `rules/PROXY_REFILTER_DOMAIN.list`; в `ROUTING-PROXY` файла `happ/geosite.dat` попадают весь `community.lst` и домены `domains_all.lst` вне зон `.ru`, `.рф`, `.su`, `.by`. Они нормализуются и проходят проверку формата, объёма и изменения состава. Используемый коммит записан в `rules/SOURCE_MANIFEST.txt`.

[MIT License репозитория](https://github.com/1andrevich/Re-filter-lists/blob/main/LICENSE)

Copyright (c) 2024 Andrevich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Re-filter агрегирует внешние входы. Его [код обработки OONI](https://github.com/1andrevich/Re-filter-lists/blob/main/src/step%205%20ooni%20list/ooni_list.py) использует измерения OONI, для которых опубликованы отдельные [условия CC BY-NC-SA 4.0](https://github.com/ooni/license/blob/master/data/LICENSE.md). Лицензия MIT самого Re-filter не подтверждает права на каждый входной набор или на публичное переиздание объединённого бинарника; это требует отдельной проверки перед публикацией.

## Loyalsoldier GeoIP

Российские IP-диапазоны из [`Loyalsoldier/geoip`](https://github.com/Loyalsoldier/geoip) `release/text/ru.txt` преобразуются в `rules/DIRECT_IP.list` и категорию `RU` файла `happ/geoip.dat`. Используемый коммит записан в `rules/SOURCE_MANIFEST.txt`. Это изменение формата и объединение с private диапазонами; исходный список не изменяет географическую классификацию.

Репозиторий публикует [CC BY-SA 4.0](https://github.com/Loyalsoldier/geoip/blob/master/LICENSE). Производная категория `RU` и её извлечение распространяются с указанием источника и на тех же условиях. README проекта указывает MaxMind GeoLite2 Country как исходную базу; условия MaxMind для самостоятельной публичной перепубликации необходимо проверить отдельно.
