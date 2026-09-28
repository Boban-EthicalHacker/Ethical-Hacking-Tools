# iOS — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем iOS дела пројекта.

## Тренутно стање

### recon

- **static** — завршено, 12 модула (изједначено са Android-ом)
  - ipa_info — основне информације из Info.plist
  - binary_info — информације о Mach-O бинару
  - files_list — листа фајлова у .app фолдеру
  - plist_full — цео Info.plist у XML облику
  - strings_scan — URL-ови, IP адресе, емаилови, API кључеви
  - ipa_hash — MD5, SHA-1, SHA-256 отисци
  - check_encryption — провера стварне шифрованости бинара
  - frameworks — анализа .framework фолдера
  - entitlements — системске дозволе из mobileprovision
  - asset_car — анализа Assets.car (компајлирани ресурси)
  - ats_check — App Transport Security провера
  - localization — језици и .lproj фолдери
  - _loader.py — заједничка функција за учитавање IPA фајла

- **live** — празно
  - (чека модуле за рад са уређајем)

### exploits

- празно

### post

- празно

### payloads

- празно

## Инфраструктура (заједничка)

- `core/menu.py` — ask_choice() функција за све меније
- `exceptions.py` — ExitApp изузетак за излаз из апликације
- Менији имају `back` и `exit` у свим нивоима

## Зависности

- `lief>=1.0.0` — Mach-O, ELF, PE бинарни формати
- `plistlib` — стандардна Python библиотека за plist
- `struct`, `hashlib`, `zipfile` — стандардне библиотеке

## Шта је урађено у овом кораку

- Направљена структура iOS фолдера
- Направљен `_loader.py` за IPA фајлове
- Направљено 12 модула у recon/static
- Тестирано на CTFApp.ipa

## Шта открива тестни узорак (CTFApp)

- Bundle ID: com.iosctf.app
- Минимални iOS: 16.0
- Архитектура: arm64, бинар није стварно шифрован
- 28 линкованих системских библиотека
- URL-ови ка CTF изазовима
- Assets.car у BOMS формату (новији)
- Нема frameworks, entitlements, ни локализација

## Следеће на реду (опционо)

iOS static — могућа проширења:
- app_extensions — анализа .appex фолдера (widgets, extensions)
- ipa_compare — поређење два IPA фајла
- car_extract — екстракција слика из Assets.car
  (захтева спољне алате или дубљи парсер)

iOS live — тек почети:
- Ограничене могућности на Linux-у
- Захтева macOS или специјализоване алате

## Остали системи

- Linux — само мени категорија, без модула
- macOS — само мени категорија, без модула
- Windows — само мени категорија, без модула
- Android — 12 модула у recon/static (завршено)
- iOS — 12 модула у recon/static (завршено)

## Структура iOS фолдера
