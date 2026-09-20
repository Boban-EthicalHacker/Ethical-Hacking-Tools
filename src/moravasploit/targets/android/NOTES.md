# Android — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем Android дела пројекта.

## Тренутно стање

### recon

- **static** — завршено
  - apk_info — приказује основне информације из APK фајла
  - permissions — приказује дозволе које апликација тражи
  - _loader.py — заједничка функција за учитавање APK-а

- **live** — празно
  - (чека модуле за рад преко ADB-а)

### exploits

- празно

### post

- празно

### payloads

- празно

## Следеће на реду

- static: exported — извезене компоненте (активности, сервиси, пријемници)
- static: certificate — сертификат апликације
- static: network_config — мрежна конфигурација
- live: adb_basic — основа за рад са уређајем

## Структура фолдера

android/
├── NOTES.md
├── init.py
├── recon/
│ ├── init.py
│ ├── static/
│ │ ├── init.py
│ │ ├── _loader.py
│ │ ├── apk_info.py
│ │ └── permissions.py
│ └── live/
│ └── init.py
├── exploits/
├── post/
└── payloads/

