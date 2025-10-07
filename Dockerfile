# === Этап 1: Сборка jsluice на Go ===
FROM golang:1.22 AS go-builder
RUN go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# === Этап 2: Лёгкий Python-образ ===
FROM python:3.10-slim

# Установка только необходимого
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /tools

# Копируем ТОЛЬКО бинарник jsluice (весит ~5–10 МБ)
COPY --from=go-builder /go/bin/jsluice /tools/jsluice

ENV PATH="/tools:${PATH}"

# Устанавливаем SecretFinder
RUN git clone https://github.com/m4ll0k/SecretFinder.git /tools/SecretFinder
RUN pip install --no-cache-dir -r /tools/SecretFinder/requirements.txt

# Ваши зависимости
RUN pip install --no-cache-dir requests

COPY js_analyzer.py /app/

ENTRYPOINT ["python3", "/app/js_analyzer.py"]
# CMD ["python3", "/app/js_analyzer.py", "--help"]