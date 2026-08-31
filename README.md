## Port Scanner (TCP)

Многоязычная утилита для сканирования TCP-портов удалённых хостов.  
Поддерживает сканирование отдельных портов, диапазонов и списков, многопоточность, настраиваемые таймауты и вывод в различных форматах.

## Особенности
- Сканирование TCP-портов с определением состояния: **open** (успешное соединение), **closed** (отказ в соединении), **filtered** (таймаут/отсутствие ответа).
- Поддержка указания портов в формате: `80`, `22,443`, `1-1024`, или комбинации.
- Настраиваемое количество потоков для параллельного сканирования.
- Настраиваемый таймаут соединения (в секундах).
- Вывод результатов в консоль с цветовой индикацией (где поддерживается).
- Экспорт в JSON и CSV для дальнейшего анализа.
- Работа на всех основных платформах (Windows, Linux, macOS).

## Установка и запуск
Для каждого языка требуются соответствующие инструменты и зависимости.

### Запуск на разных языках

1. **Python**  
   Установка: `pip install colorama` (опционально).  
   Запуск: `python port_scanner.py --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

2. **JavaScript (Node.js)**  
   Установка: `npm install commander chalk`  
   Запуск: `node port_scanner.js --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

3. **Go**  
   Запуск: `go run port_scanner.go --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

4. **Rust**  
   Сборка: `cargo build --release`  
   Запуск: `cargo run -- --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

5. **Java**  
   Сборка: `javac -cp gson.jar PortScanner.java`  
   Запуск: `java -cp .;gson.jar PortScanner --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

6. **C# (.NET Core)**  
   Установка: `dotnet add package Newtonsoft.Json`  
   Запуск: `dotnet run -- --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

7. **C++ (Linux)**  
   Требуется компилятор с C++11 и библиотека nlohmann/json.  
   Сборка: `g++ -std=c++11 -o port_scanner port_scanner.cpp -ljsoncpp -lpthread`  
   Запуск: `./port_scanner --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

8. **Kotlin (JVM)**  
   Сборка: `kotlinc -cp gson.jar PortScanner.kt`  
   Запуск: `kotlin -cp .;gson.jar PortScannerKt --host example.com --ports 22,80,1-100 --threads 20 --timeout 2 --json result.json`

## Использование

Общие аргументы командной строки (везде, где поддерживается):

- `--host <IP/домен>` – целевой хост (обязательно).
- `--ports <список>` – порты для сканирования. Форматы: `80`, `22,443`, `1-1024`, `22,80-90`.
- `--timeout <сек>` – таймаут соединения (по умолчанию 2).
- `--threads <число>` – количество потоков (по умолчанию 10).
- `--json <файл>` – экспорт в JSON.
- `--csv <файл>` – экспорт в CSV.
- `--verbose` – подробный вывод (каждый порт).
- `--no-color` – отключить цветной вывод.

Пример (Python):
```bash
python port_scanner.py --host scanme.nmap.org --ports 22,80,443,1-1000 --threads 50 --timeout 3 --json scan.json
Пример вывода (цветной):

text
Scanning scanme.nmap.org (45.33.32.156)...
Port 22/tcp   open
Port 80/tcp   open
Port 443/tcp  open
Port 1/tcp    filtered
...
Структура репозитория
text
/
├── README.md
├── port_scanner.py
├── port_scanner.js
├── port_scanner.go
├── port_scanner.rs
├── PortScanner.java
├── PortScanner.cs
├── port_scanner.cpp
└── PortScanner.kt
Лицензия
MIT
