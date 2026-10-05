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

### recon / network — 6 модула — ЗАВРШЕНО ✓

- network_info — интерфејси, IP адресе, руте, DNS
- open_ports — отворени портови (чита /proc/net/)
- listening_services — процеси који слушају (ss/netstat)
- firewall_rules — ufw, firewalld, nftables, iptables
- dns_config — resolv.conf, hosts, nsswitch, systemd-resolved
- arp_table — ARP кеш, gateway, дупликати

### recon / services — 6 модула — ЗАВРШЕНО ✓

- services — systemd сервиси
- processes — активни процеси (чита /proc/)
- cron_jobs — cron, cron.d, периодични, кориснички
- timers — systemd timers
- startup_scripts — rc.local, init.d, profile.d, autostart
- sockets — systemd socket јединице

### recon / software — 6 модула — ЗАВРШЕНО ✓

- installed_packages — dpkg, rpm, pacman, apk, snap, flatpak
- outdated_packages — застарели пакети, security updates
- docker — контејнери, слике, мреже, volumes
- compilers — 30+ компајлера и интерпретера
- suid_interpreters — SUID интерпретери (GTFOBins листа)
- language_packages — pip, npm, gem, go, cargo

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

- **36 модула** у recon
  - system: 6 ✓
  - users: 6 ✓
  - filesystem: 6 ✓
  - network: 6 ✓
  - services: 6 ✓
  - software: 6 ✓
- **9 подкатегорија** у recon
- **Завршене подкатегорије:** System, Users, Filesystem,
  Network, Services, Software

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
- Firewall на систему није активан (нема nftables правила).
- Систем користи `ss` за мрежне информације (не `netstat`).
- Модул `sockets` подржава **netlink формат** са додатном
  Port ID колоном.
- Модул `startup_scripts` има whitelist за `x11-common`
  и сличне системске скрипте.
- Модул `language_packages` чита пакете из тренутног `.venv`,
  не глобалне системске Python пакете (то је очекивано
  понашање).
- Docker није инсталиран на тестном систему.
- Систем има 4171 dpkg пакет, 268 доступних надоградњи.

## Следеће на реду

### Security подкатегорија

- selinux_apparmor — SELinux/AppArmor статус
- fail2ban — fail2ban конфигурација
- audit_rules — audit правила
- sshd_config — SSH сервер
- tls_certs — TLS сертификати на систему
- security_modules — учитани LSM модули

### Credentials подкатегорија

- ssh_private_keys — приватни SSH кључеви
- history_files — историја команди
- config_secrets — тајне у конфиг фајловима
- cloud_creds — AWS, GCP, Azure креденцијали
- browser_data — подаци из browser-а
- git_credentials — git credentials

### Logs подкатегорија

- auth_logs — /var/log/auth.log
- system_logs — /var/log/syslog
- journal — systemd journal
- app_logs — логови апликација
- kernel_logs — /var/log/kern.log
- audit_logs — /var/log/audit/

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
│ │ ├── init.py
│ │ ├── network_info.py
│ │ ├── open_ports.py
│ │ ├── listening_services.py
│ │ ├── firewall_rules.py
│ │ ├── dns_config.py
│ │ └── arp_table.py
│ ├── services/
│ │ ├── init.py
│ │ ├── services.py
│ │ ├── processes.py
│ │ ├── cron_jobs.py
│ │ ├── timers.py
│ │ ├── startup_scripts.py
│ │ └── sockets.py
│ ├── software/
│ │ ├── init.py
│ │ ├── installed_packages.py
│ │ ├── outdated_packages.py
│ │ ├── docker.py
│ │ ├── compilers.py
│ │ ├── suid_interpreters.py
│ │ └── language_packages.py
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
- Firewall: неактиван
- Мрежа: wlan0 (UP), eth0 (DOWN)
- Docker: није инсталиран