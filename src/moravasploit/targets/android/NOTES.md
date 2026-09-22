# Android — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем Android дела пројекта.

## Тренутно стање

### recon

- **static** — завршено
  - apk_info — основне информације из APK фајла
  - permissions — све дозволе које апликација тражи
  - exported — извезене компоненте (експлицитне и имплицитне)
  - certificate — сертификат апликације (subject, issuer, отисци)
  - network_config — мрежна безбедносна конфигурација
  - dangerous_permissions — опасне дозволе са упозорењем
  - strings_scan — претрага URL-ова, IP адреса, емаилова, API кључева
  - manifest_dump — цео AndroidManifest.xml са синтаксним истицањем
  - _loader.py — заједничка функција за учитавање APK-а

- **live** — празно
  - (чека модуле за рад преко ADB-а)

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

## Следеће на реду

Android static (још могуће):
- native_libs — листа .so нативних библиотека
- assets_scan — преглед assets/ фолдера (конфизи, базе, кључеви)
- sdk_info — детаљне информације о SDK верзијама

Android live (тек почети):
- adb_basic — основа за рад са уређајем
- adb_devices — листа повезаних уређаја

## Остали системи

- Linux — само мени категорија, без модула
- macOS — само мени категорија, без модула
- Windows — само мени категорија, без модула
- iOS — само мени категорија, без модула

## Структура Android фолдера

android/
├── NOTES.md
├── init.py
├── recon/
│ ├── init.py
│ ├── static/
│ │ ├── init.py
│ │ ├── _loader.py
│ │ ├── apk_info.py
│ │ ├── permissions.py
│ │ ├── exported.py
│ │ ├── certificate.py
│ │ ├── network_config.py
│ │ ├── dangerous_permissions.py
│ │ ├── strings_scan.py
│ │ └── manifest_dump.py
│ └── live/
│ └── init.py
├── exploits/
├── post/
└── payloads/