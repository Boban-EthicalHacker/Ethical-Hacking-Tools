# iOS — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем iOS дела пројекта.

## Тренутно стање

### recon

- **static** — у току, 1 модул
  - ipa_info — основне информације из Info.plist
    (bundle ID, верзија, минимални iOS, дозволе)
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

## Шта је урађено у овом кораку

- Направљена структура iOS фолдера
- Направљен `_loader.py` који учитава IPA фајл (ZIP) и
  чита Info.plist (бинарни или XML)
- Направљен први модул `ipa_info`
- Повезан iOS recon мени са static/live подменијем
- Тестирано на CTFApp.ipa

## Следеће на реду

iOS static — планирани модули:
- binary_info — информације о Mach-O бинару
  (архитектуре, тип, линковане библиотеке, шифровање)
- files_list — листа свих фајлова у .app фолдеру
- plist_full — цео Info.plist у читљивом облику
- entitlements — системске дозволе (када буде доступан
  embedded.mobileprovision)
- frameworks — листа уграђених framework-а
- strings_scan — URL-ови, IP адресе, емаилови, API кључеви
- ipa_hash — MD5/SHA отисци самог IPA фајла
- cert_info — сертификат за потписивање

## Остали системи

- Linux — само мени категорија, без модула
- macOS — само мени категорија, без модула
- Windows — само мени категорија, без модула
- Android — 12 модула у recon/static (завршено)

## Структура iOS фолдера


ios/
├── NOTES.md
├── init.py
├── recon/
│ ├── init.py
│ ├── static/
│ │ ├── init.py
│ │ ├── _loader.py
│ │ └── ipa_info.py
│ └── live/
│ └── init.py
├── exploits/
├── post/
└── payloads/


## Тестни узорак
