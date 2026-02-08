# srtunectl

## Table of Contents
- Russian (Русский)
  - [Overview](#ru-overview)
  - [Features](#ru-features)
  - [Requirements](#ru-requirements)
  - [Installation](#ru-installation)
  - [Configuration](#ru-configuration)
  - [Usage](#ru-usage)
  - [systemd Service](#ru-systemd)
  - [Debugging](#ru-debugging)
  - [Contributing](#ru-contributing)
  - [License](#ru-license)
- English
  - [Overview](#en-overview)
  - [Features](#en-features)
  - [Requirements](#en-requirements)
  - [Installation](#en-installation)
  - [Configuration](#en-configuration)
  - [Usage](#en-usage)
  - [systemd Service](#en-systemd)
  - [Debugging](#en-debugging)
  - [Contributing](#en-contributing)
  - [License](#en-license)

---

## Русский

<a id="ru-overview"></a>
### Overview
srtunectl — лёгкая утилита для управления системными маршрутами (`ip route`) на основе конфигурационного файла. Предназначена для маршрутизации через туннельные интерфейсы (например, `tun` интерфейсы, используемые ss-tun или другими туннелями). Утилита добавляет и удаляет маршруты в соответствии с конфигом и может работать как демон systemd.

Все JSON-файлы в каталоге `data` обрабатываются и добавляются как маршруты через указанный tun-интерфейс. Также можно задать принудительные маршруты через папку `default_route`.

<a id="ru-features"></a>
### Возможности
- Управление маршрутами через простой конфигурационный файл  
- Автоматическая маршрутизация выбранных подсетей через tun-интерфейс  
- Обработка JSON-файлов маршрутов из папки `data`  
- Принудительная установка отдельных маршрутов через `default_route`  
- Запуск вручную или как systemd-сервис  
- Простая сборка и установка через `make`

<a id="ru-requirements"></a>
### Требования
- Linux с установленными iproute2 (`ip` команда)  
- Go toolchain (для сборки из исходников)  
- Привилегии root для изменения системных маршрутов

<a id="ru-installation"></a>
### Установка
1. Скопируйте пример конфигурации:
```bash
cp srtunectl.conf.example srtunectl.conf
```

2. Соберите бинарник:
```bash
make
```

3. Установите и зарегистрируйте systemd-сервис (Makefile выполняет установку и включение сервиса):
```bash
sudo make install
```

Примечания по установке (соответствует Makefile в репозитории):
- Бинарник устанавливается в `/usr/bin/srtunectl`.  
- Makefile генерирует systemd-unit `/etc/systemd/system/srtuncectl.service` из шаблона `srtunectl.service.in` и вызывает `systemctl daemon-reload` и `systemctl enable srtunectl.service`.

<a id="ru-configuration"></a>
### Конфигурация
Файл примера: `srtunectl.conf.example`. В конфигурации обычно указываются:

- Список сетей или подсетей для маршрутизации  
- Имя tun-интерфейса (например, `tun0`)  
- Адрес шлюза (gateway) для туннеля  
- Опционально: адрес(а) дефолтного шлюза и интерфейс по умолчанию  
- Пути к папкам `data` и `default_route` (если используются нестандартные)

Формат маршрутов (пример в одной строке):  
`networks = [ "8.8.8.0/24", "1.1.1.0/24" ]`

Описание: это пример того, в каком формате программа srtunectl ожидает список маршрутов (поле `networks`). srtunectl парсит записи в таком виде и добавляет соответствующие подсети в таблицу маршрутизации через настроенный tun-интерфейс.

<a id="ru-usage"></a>
### Использование
Запуск вручную:
```bash
sudo srtunectl
```

Проверка текущих маршрутов:
```bash
ip route
```

Проверить статус systemd-сервиса (если вы устанавливали через `make install`):
```bash
sudo systemctl status srtunectl.service
```

Просмотр логов сервиса:
```bash
sudo journalctl -u srtunectl.service -f
```

<a id="ru-debugging"></a>
### Отладка
- Проверьте, что tun-интерфейс создан и доступен:
```bash
ip a
```
- Убедитесь, что в `srtunectl.conf` корректно указаны gateway, имя интерфейса и подсети.  
- Проверьте валидность JSON-файлов в папке `data`.  
- Просмотрите логи systemd при запуске как службы:
```bash
sudo journalctl -u srtunectl.service
```
- Запускайте утилиту вручную под sudo, чтобы увидеть вывод в консоли:
```bash
sudo srtunectl
```

<a id="ru-contributing"></a>
### Вклад
PR, репорты об ошибках и предложения по улучшению приветствуются. Пожалуйста, открывайте issues с описанием проблемы и шагами для воспроизведения.

<a id="ru-license"></a>
### Лицензия
Файл LICENSE в корне репозитория содержит условия лицензии проекта.

---

## English

<a id="en-overview"></a>
### Overview
srtunectl is a lightweight utility to manage system routes (`ip route`) based on a configuration file. It is intended for routing via tunnel interfaces (for example, `tun` interfaces used by ss-tun or other tunnels). The tool adds and removes routes according to the configuration and can run as a systemd service.

All JSON files located in the `data` folder are parsed and added as routes through the specified tun device. You can also define forced routes via the `default_route` folder.

<a id="en-features"></a>
### Features
- Manage routes via a simple configuration file  
- Automatically route selected subnets through a tun interface  
- Process JSON route files from the `data` folder  
- Force specific routes via `default_route`  
- Run manually or as a systemd service  
- Easy build and installation via `make`

<a id="en-requirements"></a>
### Requirements
- Linux with iproute2 (`ip` command)  
- Go toolchain (to build from source)  
- Root privileges to modify system routes

<a id="en-installation"></a>
### Installation
1. Copy the example configuration:
```bash
cp srtunectl.conf.example srtunectl.conf
```

2. Build the binary:
```bash
make
```

3. Install and register the systemd service (Makefile performs service install and enable):
```bash
sudo make install
```

Notes regarding installation (matches Makefile in repository):
- The binary is installed to `/usr/bin/srtunectl`.  
- The Makefile generates the systemd unit `/etc/systemd/system/srtunectl.service` from the template `srtunectl.service.in` and runs `systemctl daemon-reload` and `systemctl enable srtunectl.service`.

<a id="en-configuration"></a>
### Configuration
Example config file: `srtunectl.conf.example`. Typically the configuration includes:

- List of networks or subnets to route  
- Tun interface name (e.g., `tun0`)  
- Gateway address for the tunnel  
- Optional: default gateway(s) and default interface  
- Paths to `data` and `default_route` folders (if using non-default locations)

Routes format (example in one line):  
`networks = [ "8.8.8.0/24", "1.1.1.0/24" ]`

Description: this is an example of the format in which srtunectl expects the list of routes (the `networks` field). srtunectl parses entries in this form and installs the corresponding subnets into the routing table via the configured tun interface.

<a id="en-usage"></a>
### Usage
Run manually:
```bash
sudo srtunectl
```

Check routes:
```bash
ip route
```

Check systemd service status (if installed via `make install`):
```bash
sudo systemctl status srtunectl.service
```

View service logs:
```bash
sudo journalctl -u srtunectl.service -f
```

<a id="en-debugging"></a>
### Debugging
- Ensure the tun interface exists:
```bash
ip a
```
- Verify gateway, interface name, and subnets in `srtunectl.conf`.  
- Validate JSON files in the `data` folder.  
- Check systemd logs when running as a service:
```bash
sudo journalctl -u srtunectl.service
```
- Run the tool manually under sudo to see console output:
```bash
sudo srtunectl
```

<a id="en-contributing"></a>
### Contributing
Pull requests, bug reports, and feature suggestions are welcome. Please open issues with a description and steps to reproduce.

<a id="en-license"></a>
### License
See the LICENSE file in the repository for licensing information.
