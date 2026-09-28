# Linux — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем Linux дела пројекта.

## Тренутно стање

Linux recon је организован по **подкатегоријама** (слично
као мобилне платформе, али другачије подељено — по темама).

### recon / system — 2 модула

- system_info — hostname, OS, kernel, архитектура, uptime
- kernel_info — верзија кернела, boot параметри, модули, sysctl

### recon / users — 1 модул

- users_groups — корисници, групе, UID 0, sudo конфигурација

### recon / filesystem — 1 модул

- suid_sgid — фајлови са SUID/SGID битовима

### recon / network — празно

- (чека модуле)

### recon / services — празно

- (чека модуле)

### recon / software — празно

- (чека модуле)

### recon / security — празно

- (чека модуле)

### recon / credentials — празно

- (чека модуле)

### recon / logs — празно

- (чека модуле)

### exploits

- празно

### post

- празно

### payloads

- празно

## Укупно

- **4 модула** у recon (system, users, filesystem)
- **9 подкатегорија** у recon

## Инфраструктура (заједничка)

- `core/menu.py`:
  - `ask_choice()` — нумерички унос (стари стил)
  - `ask_select()` — стрелице горе/доле (нови стил)
- `exceptions.py` — ExitApp изузетак
- Кратки тастери у менијима: `b` = back, `e` = exit
- Linux користи `ask_select()` свуда

## Зависности (у pyproject.toml)

- `rich>=13.7` — леп приказ
- `questionary>=2.1.1` — менији са стрелицама
- `pyaxmlparser>=0.3.31` — за Android
- `lief>=1.0.0` — за бинарне формате (iOS, касније Linux)

## Следеће на реду

### Прво завршити system подкатегорију

- hardware_info — CPU, RAM, дискови, GPU
- boot_info — bootloader, init систем
- environment — променљиве окружења

### Затим остале подкатегорије (редом)

**users:**
- sudoers — детаљна sudo конфигурација
- ssh_keys — authorized_keys фајлови
- login_history — last, w, who
- password_policy — /etc/login.defs
- pam_config — PAM конфигурација

**filesystem:**
- capabilities — Linux capabilities на фајловима
- world_writable — фајлови које сви могу мењати
- hidden_files — скривене фасцикле
- recent_files — недавно измењени
- suspicious_files — фајлови на необичним местима

**network:**
- network_info — интерфејси, IP, руте
- open_ports — отворени портови
- listening_services — шта слуша
- firewall_rules — iptables/nftables/ufw
- dns_config — DNS подешавања
- arp_table — ARP кеш

**services:**
- services — systemd сервиси
- processes — активни процеси
- cron_jobs — заказани задаци
- timers — systemd timers
- startup_scripts — скрипте при покретању
- sockets — systemd sockets

**software:**
- installed_packages — инсталирани пакети
- outdated_packages — застарели
- kernel_modules — учитани модули (део у kernel_info већ)
- docker — Docker контејнери
- compilers — инсталирани компајлери

**security:**
- selinux_apparmor — SELinux/AppArmor статус
- fail2ban — fail2ban конфигурација
- audit_rules — audit правила
- sysctl — детаљни sysctl
- sshd_config — SSH сервер
- tls_certs — TLS сертификати

**credentials:**
- ssh_private_keys — приватни SSH кључеви
- history_files — историја команди
- config_secrets — тајне у конфиг фајловима
- env_secrets — тајне у environment
- cloud_creds — AWS, GCP, Azure креденцијали

**logs:**
- auth_logs — /var/log/auth.log
- system_logs — /var/log/syslog
- journal — systemd journal
- app_logs — логови апликација

## Циљ

Озбиљан Linux recon framework са ~50 модула у 9 подкатегорија.
Након тога иду exploits (~15), post (~10), payloads (~5).

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
│ ├── system/
│ │ ├── init.py
│ │ ├── system_info.py
│ │ └── kernel_info.py
│ ├── users/
│ │ ├── init.py
│ │ └── users_groups.py
│ ├── filesystem/
│ │ ├── init.py
│ │ └── suid_sgid.py
│ ├── network/
│ │ └── init.py
│ ├── services/
│ │ └── init.py
│ ├── software/
│ │ └── init.py
│ ├── security/
│ │ └── init.py
│ ├── credentials/
│ │ └── init.py
│ └── logs/
│ └── init.py
├── exploits/
├── post/
└── payloads/


## Тестни систем

- Kali GNU/Linux Rolling 2026.3
- Kernel: 7.0.12+kali-amd64
- Architecture: x86_64
- ASLR: 2 (пуно)
- kptr_restrict: 0 (упозорење — pointer-и нису скривени)
- dmesg_restrict: 0 (упозорење — dmesg доступан свима)
- yama/ptrace_scope: 0 (упозорење — ptrace није ограничен)