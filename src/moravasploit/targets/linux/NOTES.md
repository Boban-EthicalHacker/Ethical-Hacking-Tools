# Linux — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем Linux дела пројекта.

## Тренутно стање

### recon

- **директно у recon/** — 2 модула
  - system_info — основне информације о систему
    (hostname, OS, kernel, архитектура, uptime, boot time)
  - users_groups — корисници, групе, sudo права
    (UID 0, интерактивни корисници, sudo конфигурација)

Напомена: Linux нема static/live поделу као Android/iOS.
Анализа Linux система је увек "live" — чита се локални систем
или преко SSH касније.

### exploits

- празно

### post

- празно

### payloads

- празно

## Инфраструктура (заједничка)

- `core/menu.py` — две функције за меније:
  - `ask_choice()` — нумерички унос (стари стил)
  - `ask_select()` — стрелице горе/доле (нови стил)
- `exceptions.py` — ExitApp изузетак за излаз
- Linux менији користе `ask_select()` са стрелицама
- Кратки тастери: `b` = back, `e` = exit

## Зависности

- `questionary>=2.1.1` — за меније са стрелицама
- `rich>=13.7` — за леп приказ
- `lief>=1.0.0` — за бинарне формате (jош се не користи у Linux)
- `pyaxmlparser>=0.3.31` — за Android (не користи се у Linux)

## Шта је урађено у овом кораку

- Преправљен Linux мени да користи `ask_select()` (стрелице)
- Додата `ask_select()` функција у `core/menu.py`
- Додат `questionary` као зависност
- Направљена два модула у recon

## Следеће на реду

Linux recon — планирани модули:
- suid_sgid — фајлови са SUID/SGID битовима (privilege escalation)
- services — активни сервиси и отворени портови
- cron_jobs — заказани задаци
- network_info — мрежне конфигурације, руте, DNS
- ssh_config — SSH подешавања
- world_writable — фајлови које сви могу мењати
- package_audit — инсталирани пакети, верзије
- kernel_modules — учитани модули кернела
- history — историја команди корисника
- capabilities — фајлови са Linux capabilities

## Остали системи

- macOS — само мени категорија, без модула
- Windows — само мени категорија, без модула
- Android — 12 модула у recon/static (завршено)
- iOS — 12 модула у recon/static (завршено)

## Структура Linux фолдера

linux/
├── NOTES.md
├── init.py
├── recon/
│ ├── init.py
│ ├── system_info.py
│ └── users_groups.py
├── exploits/
├── post/
└── payloads/


## Тестни систем

- Kali GNU/Linux Rolling 2026.3
- Kernel: 7.0.12+kali-amd64
- Architecture: x86_64