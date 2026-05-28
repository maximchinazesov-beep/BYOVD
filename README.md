# 🛡️ Bring Your Own Vulnerable Driver (BYOVD) Research Lab

[English](#english) | [Русский](#русский)

---

## English

Welcome to my security research repository dedicated to analyzing vulnerable kernel-mode drivers (BYOVD - Bring Your Own Vulnerable Driver attacks). 

The goal of this project is to practice reverse engineering, understand Windows kernel internals, and document real-world vulnerabilities found in production software.

### 📁 Analyzed Drivers
* **[Lenovo BootRepair (bootrepair.sys)](bootrepair/)** — Recent 1-day vulnerability allowing arbitrary process termination (`ZwTerminateProcess`) from Ring 0. Features dynamic analysis, clean C++ PoC source code, and full IDA Pro database.
* **[WinRing0 (WinRing0x64.sys)](WinRing0/)** — Classic critical vulnerability enabling arbitrary MSR Read/Write (`__readmsr`/`__writemsr`) and raw I/O port access from Ring 0, leading to KASLR bypass and full Local Privilege Escalation (LPE). Features fully documented IDA Pro database.

---

## Русский

Добро пожаловать в мой исследовательский репозиторий, посвященный анализу уязвимых драйверов режима ядра (атаки класса BYOVD — Bring Your Own Vulnerable Driver).

Цель этого проекта — практика в реверс-инжиниринге, изучение внутренней архитектуры ядра Windows и документирование реальных уязвимостей, найденных в коммерческом ПО.

### 📁 Разобранные драйверы
* **[Lenovo BootRepair (bootrepair.sys)](bootrepair/)** — Свежая 1-day уязвимость, позволяющая принудительно завершать любые процессы (`ZwTerminateProcess`) из Ring 0. Внутри: технический отчет, чистый исходный код эксплойта на C++ и база данных IDA Pro.
* **[WinRing0 (WinRing0x64.sys)](WinRing0/)** — Классическая критическая уязвимость, позволяющая выполнять произвольное чтение/запись MSR-регистров (`__readmsr`/`__writemsr`) и осуществлять прямой доступ к портам ввода-вывода из Ring 0, что приводит к обходу KASLR и полной локальной эскалации привилегий (LPE). В комплект входит полностью документированная база данных IDA Pro.

---

### ⚠️ Disclaimer / Дисклеймер
*Everything published here is strictly for educational, learning, and research purposes. Author is not responsible for any misuse.*  
*Все материалы опубликованы исключительно в образовательных и исследовательских целях. Автор не несет ответственности за любое нецелевое использование.*
