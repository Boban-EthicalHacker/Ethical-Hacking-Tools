# Linux — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем Linux дела пројекта.

## Тренутно стање

Linux recon је организован по **подкатегоријама** (по темама).

### recon / system — 6 модула — ЗАВРШЕНО ✓

- system_info — hostname, OS, kernel, архитектура, uptime, boot time
- kernel_info — верзија кернела, boot параметри, модули, sysctl
- hardware_info — CPU, RAM, дискови, DMI подаци
- boot_info — init систем, GRUB конфигурација, boot entries
- environment — променљиве окружења са детекцијом осетљивих
- time_info — временска зона, NTP статус, timedatectl

### recon / users — 6 модула — ЗАВРШЕНО ✓

- users_groups — корисници, групе, UID 0
- ssh_keys — authorized_keys и known_hosts
- login_history — last/who/wtmpdb, неуспешни покушаји
- sudoers — детаљна анализа sudo конфигурације
- password_policy — политика лозинки, PAM опције
- pam_config — цела PAM конфигурација

### recon / filesystem — 6 модула — ЗАВРШЕНО ✓

- suid_sgid — фајлови са SUID/SGID битовима
- capabilities — Linux capabilities на фајловима
- world_writable — фајлови које сви могу мењати
- hidden_files — скривени фајлови на необичним локацијама
- recent_files — недавно измењени фајлови
- suspicious_files — фајлови са сумњивим именима и локацијама

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

- **18 модула** у recon
  - system: 6 ✓
  - users: 6 ✓
  - filesystem: 6 ✓
- **9 подкатегорија** у recon
- **Завршене подкатегорије:** System, Users, Filesystem

## Инфраструктура (заједничка)

- `core/menu.py`:
  - `ask_choice()` — нумерички унос (стари стил)
  - `ask_select()` — стрелице горе/доле (нови стил)
- `core/session.py` — управљање сесијом:
  - `start_session(target)` — прави нови фолдер у logs/
  - `end_session()` — завршава сесију
  - `save(module, data)` — чува JSON у текућу сесију
- `exceptions.py` — ExitApp изузетак
- Кратки тастери: `b` = back, `e` = exit
- Linux користи `ask_select()` свуда

## Како ради сесија

1. Кад уђеш у Linux, прави се фолдер:
   `logs/linux_YYYY-MM-DD_HH-MM-SS/`
2. Сваки модул након извршења чува JSON фајл у тај фолдер:
   `logs/linux_.../system_info.json`
3. JSON садржи: `module`, `saved_at`, `data`.
4. Кад изађеш из Linux менија, сесија се завршава али фолдер остаје.
5. Старе сесије бришеш ручно.

## Зависности (у pyproject.toml)

- `rich>=13.7` — леп приказ
- `questionary>=2.1.1` — менији са стрелицама
- `pyaxmlparser>=0.3.31` — за Android
- `lief>=1.0.0` — за бинарне формате (iOS, касније Linux)

## Специфичности тестног система

- Kali GNU/Linux Rolling 2026.3 користи **wtmpdb** уместо
  класичних `last`/`lastb` команди. Модул `login_history`
  подржава оба система.
- `/etc/sudoers` захтева root за читање. За потпуну анализу
  покренути са:
  `sudo /home/boban/my-projects/moravasploit/.venv/bin/moravasploit`
- `/home/boban` има дозволу 777 (намерно, због Laravel
  пројеката). Модули који претражују систем третирају
  `/home/` као нормалну локацију.

## Следеће на реду

### Network подкатегорија

- network_info — интерфејси, IP, руте
- open_ports — отворени портови (локално)
- listening_services — који сервиси слушају
- firewall_rules — iptables/nftables/ufw
- dns_config — DNS подешавања
- arp_table — ARP кеш

### Services подкатегорија

- services — systemd сервиси
- processes — активни процеси
- cron_jobs — заказани задаци
- timers — systemd timers
- startup_scripts — скрипте при покретању
- sockets — systemd sockets

### Software подкатегорија

- installed_packages — инсталирани пакети
- outdated_packages — застарели
- docker — Docker контејнери
- compilers — инсталирани компајлери

### Security подкатегорија

- selinux_apparmor — SELinux/AppArmor статус
- fail2ban — fail2ban конфигурација
- audit_rules — audit правила
- sshd_config — SSH сервер
- tls_certs — TLS сертификати

### Credentials подкатегорија

- ssh_private_keys — приватни SSH кључеви
- history_files — историја команди
- config_secrets — тајне у конфиг фајловима
- cloud_creds — AWS, GCP, Azure креденцијали

### Logs подкатегорија

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
│ │ ├── kernel_info.py
│ │ ├── hardware_info.py
│ │ ├── boot_info.py
│ │ ├── environment.py
│ │ └── time_info.py
│ ├── users/
│ │ ├── init.py
│ │ ├── users_groups.py
│ │ ├── ssh_keys.py
│ │ ├── login_history.py
│ │ ├── sudoers.py
│ │ ├── password_policy.py
│ │ └── pam_config.py
│ ├── filesystem/
│ │ ├── init.py
│ │ ├── suid_sgid.py
│ │ ├── capabilities.py
│ │ ├── world_writable.py
│ │ ├── hidden_files.py
│ │ ├── recent_files.py
│ │ └── suspicious_files.py
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
- CPU: Intel i5-12500H
- RAM: 15.33 GB
- Timezone: Europe/Belgrade
- Login system: wtmpdb