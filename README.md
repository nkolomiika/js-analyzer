# JS Analyzer — Анализатор JavaScript-файлов для поиска endpoint'ов и секретов

Этот инструмент автоматизирует анализ JavaScript-файлов с целью:
- **Обнаружения API-эндпоинтов** (URL, методы, параметры)
- **Поиска чувствительных данных** (API-ключи, токены, пароли и др.)

Использует два open-source инструмента:
- [`jsluice`](https://github.com/BishopFox/jsluice) — для извлечения URL и HTTP-методов
- [`SecretFinder`](https://github.com/m4ll0k/SecretFinder) — для поиска секретов

Результаты сохраняются в удобном **HTML-отчёте** с гиперссылками и структурированным выводом.

---

## 📦 Требования

- Docker **ИЛИ**
- Python 3.10+, Go 1.22+, `jsluice`, `SecretFinder`

---

## 🔽 Установка

```bash
git clone https://github.com/nkolomiika/js-analyzer.git
```

## 🐳 Быстрый старт с Docker

### 1. Соберите образ

```bash
docker build -t js-analyzer:latest .
```

### 2. Подготовьте файл со списком JS-URL
Создайте файл, например js_urls.txt, с одним URL на строку

```bash
cat js_urls.txt
https://example.com/static/main.js
https://example.com/app/bundle.js
```

### 3. Запустите анализ

```bash
docker run --rm -v $(pwd):/work js-analyzer:latest /work/js_urls.txt
```

## 🖥️ Локальный запуск (без Docker)

### 1. Установка зависимостей

```bash

# Установка jsluice (требуется Go)
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# Установка SecretFinder
git clone https://github.com/m4ll0k/SecretFinder.git /tools/SecretFinder
pip install -r /tools/SecretFinder/requirements.txt

# Установка Python-зависимостей
pip install requests
```

### 2. Запуск
```bash
python3 js_analyzer.py js_urls.txt
```
