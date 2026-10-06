# Linux — напредак

Овај фајл служи као кратак подсетник докле се стигло
са развојем Linux дела пројекта.

## Тренутно стање

Linux recon је организован по **подкатегоријама** (по темама).
Свих 9 подкатегорија је завршено — укупно **54 модула**.

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

### recon / security — 6 модула — ЗАВРШЕНО ✓

- selinux_apparmor — SELinux/AppArmor статус, LSM модули
- fail2ban — fail2ban jail конфигурација
- audit_rules — audit правила и конфигурација
- sshd_config — SSH сервер конфигурација са препорукама
- tls_certs — CA сертификати, приватни кључеви, истекли
- security_modules — LSM модули, kernel hardening, CPU рањивости

### recon / credentials — 6 модула — ЗАВРШЕНО ✓

- ssh_private_keys — приватни SSH кључеви, шифрованост
- history_files — историја команди, осетљиве команде
- config_secrets — .env, AWS, Docker, git креденцијали
- cloud_creds — AWS, GCP, Azure, Kubernetes креденцијали
- browser_data — Firefox, Chrome, Brave профили и подаци
- git_credentials — .gitconfig, .git-credentials, remote URL-ови

### recon / logs — 6 модула — ЗАВРШЕНО ✓

- auth_logs — auth логови, systemd journal fallback
- system_logs — /var/log/syslog, journal, грешке по сервису
- journal — systemd journal, boot историја, disk usage
- app_logs — web, DB, mail логови, детекција напада
- kernel_logs — dmesg, kernel грешке, OOM, USB догађаји
- audit_logs — audit записи, AVC деније, EXECVE команде

## Укупно

- **54 модула** у recon
  - system: 6 ✓
  - users: 6 ✓
  - filesystem: 6 ✓
  - network: 6 ✓
  - services: 6 ✓
  - software: 6 ✓
  - security: 6 ✓
  - credentials: 6 ✓
  - logs: 6 ✓
- **9 подкатегорија** у recon
- **Linux recon је COMPLETE** ✓

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
  класичних `last`/`lastb` команди.
- `/etc/sudoers` захтева root за читање:
  `sudo /home/boban/my-projects/moravasploit/.venv/bin/moravasploit`
- `/home/boban` има дозволу 777 (намерно, због Laravel
  пројеката).
- Firewall није активан (нема nftables правила).
- Систем користи `ss` (не `netstat`).
- Модул `sockets` подржава netlink формат.
- Docker није инсталиран.
- fail2ban није инсталиран.
- auditd није инсталиран.
- AppArmor модул учитан, али нема профила.
- Систем има 122 CA сертификата.
- CPU има све рањивости митиговане.
- 4171 dpkg пакет, 268 надоградњи.
- Journal је persistent (872.9M, 175 boot-ова).
- Корисник има више GitHub налога.
- 98 .env фајлова у пројектима.
- 9 приватних SSH кључева (1 са слабим permissions).

## Следеће на реду

Linux recon је завршен. Следеће фазе пројекта:

## exploits — 15 модула — ЗАВРШЕНО ✓

Сви модули у овој категорији су за **ДЕТЕКЦИЈУ**.
Само проверавају да ли верзија/конфигурација одговара познатој
рањивости. Не покушавају експлоатацију.

### exploits / kernel — 2 модула — ЗАВРШЕНО ✓

- kernel_version_check — упоређивање верзије кернела са познатим рањивим
- kernel_hardening_check — kernel hardening опције (KASLR, SMEP, SMAP, ...)

### exploits / cve — 7 модула — ЗАВРШЕНО ✓

- pwnkit — PwnKit (CVE-2021-4034, pkexec)
- dirty_pipe — Dirty Pipe (CVE-2022-0847)
- sudo_baron_samedit — Baron Samedit (CVE-2021-3156)
- sudo_all_bypass — sudo Runas ALL bypass (CVE-2019-14287)
- polkit_cve — polkit privilege escalation (CVE-2021-3560)
- glibc_ghost — glibc GHOST (CVE-2015-0235)
- netfilter_cve — Netfilter (CVE-2021-22555, CVE-2022-25636, CVE-2022-1015)

### exploits / privilege — 4 модула — ЗАВРШЕНО ✓

- suid_exploit_check — SUID фајлови против GTFOBins листе
- capabilities_exploit — злоупотребљиве Linux capabilities
- sudo_gtfobins — sudo дозволе против GTFOBins листе
- package_cve_check — инсталирани пакети против CVE базе

### exploits / container — 2 модула — ЗАВРШЕНО ✓

- lxd_check — LXD/LXC привилегије (ескалација кроз групу)
- container_escape_check — услови за излаз из контејнера

- **15 модула** у exploits
  - kernel: 2 ✓
  - cve: 7 ✓
  - privilege: 4 ✓
  - container: 2 ✓
- **4 подкатегорије** у exploits
- **Linux exploits је COMPLETE** ✓

### post (~10 модула)

Екстракција података и анализа конфигурација након приступа.

Планирани модули:
- data_extraction — прикупљање корисничких података
- config_dump — dump конфигурационих фајлова
- password_hashes — екстракција /etc/shadow (само ако је доступно)
- ssh_key_dump — прикупљање SSH кључева
- browser_data_dump — екстракција browser података
- history_dump — dump историје команди
- network_pivot — преглед мрежа за даље ширење
- process_injection_check — могућност ptrace
- persistence_check — постојећи persistence механизми
- cleanup — уклањање трагова (само у овлашћеном тесту)

### payloads (~5 модула)

Бенигни тестни садржај за проверу детекције.

Планирани модули:
- reverse_shell_bash — бенигни reverse shell за тест
- reverse_shell_python — Python reverse shell
- bind_shell_nc — netcat bind shell
- msfvenom_wrapper — wrapper око msfvenom (ако је инсталиран)
- payload_encoder — енкодер за payload

**Важна напомена:** Сви payload модули су само за овлашћено
тестирање. Не смеју се користити против система без дозволе.

## Циљ

Комплетан Linux framework са:
- ~54 recon модула ✓
- ~15 exploits модула
- ~10 post модула
- ~5 payloads модула

Укупно око **84 модула** за Linux.

## Остали системи

- macOS — само мени категорија, без модула
- Windows — само мени категорија, без модула
- Android — 12 модула у recon/static (завршено)
- iOS — 12 модула у recon/static (завршено)

## Структура Linux фолдера

linux/
├── NOTES.md
├── __init__.py
├── recon/
│   ├── __init__.py
│   ├── system/       (6 модула) ✓
│   ├── users/        (6 модула) ✓
│   ├── filesystem/   (6 модула) ✓
│   ├── network/      (6 модула) ✓
│   ├── services/     (6 модула) ✓
│   ├── software/     (6 модула) ✓
│   ├── security/     (6 модула) ✓
│   ├── credentials/  (6 модула) ✓
│   └── logs/         (6 модула) ✓
├── exploits/
│   ├── __init__.py
│   └── (15 модула) ✓
├── post/
│   └── (планирано ~10 модула)
└── payloads/
    └── (планирано ~5 модула)

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
- fail2ban: није инсталиран
- auditd: није инсталиран
- SELinux: није доступан
- AppArmor: модул учитан, нема профила
- Journal: persistent, 872.9M
- CPU рањивости: све митиговане