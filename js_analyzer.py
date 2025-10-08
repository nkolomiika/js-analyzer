import os
import json
import requests
import subprocess
import argparse
from urllib.parse import urlparse

# === КОНФИГУРАЦИЯ ДЛЯ DOCKER ===
JSLUICE_EXEC = "jsluice"  # установлен в PATH
SECRET_FINDER_PY = "/tools/SecretFinder/SecretFinder.py"
PYTHON_EXEC = "python3"   # python3 в PATH
WORK_DIR = "/work"        # монтируется извне через -v
JS_BASE_DIR = os.path.join(WORK_DIR, "js_files")
REPORTS_DIR = WORK_DIR    

os.makedirs(JS_BASE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def download_js_files(urls_file):
    downloaded_info = [] 

    with open(urls_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        try:
            parsed_url = urlparse(url)
            scheme = parsed_url.scheme or 'http'
            domain = parsed_url.netloc
            if not domain:
                print(f"[-] Пропущен URL без домена: {url}")
                continue

            path = parsed_url.path
            filename = os.path.basename(path) or "index.js"

            domain_dir = os.path.join(JS_BASE_DIR, domain)
            os.makedirs(domain_dir, exist_ok=True)
            save_path = os.path.join(domain_dir, filename)

            response = requests.get(url, timeout=15)
            response.raise_for_status()

            with open(save_path, 'wb') as out_file:
                out_file.write(response.content)

            downloaded_info.append((os.path.abspath(save_path), domain, url, scheme))
            print(f"[+] Скачано: {url} → {save_path}")

        except Exception as e:
            print(f"[-] Ошибка при скачивании {url}: {e}")

    return downloaded_info


def process_endpoint(raw_line, domain, scheme):
    line = raw_line.strip()
    if not line:
        return line, line

    if line.startswith(('http://', 'https://')):
        return line, line

    if line.startswith('/'):
        absolute_url = f"{scheme}://{domain}{line}"
        display_text = f"{line} → {absolute_url}"
        return display_text, absolute_url

    # Относительный путь без / — делаем абсолютным
    absolute_url = f"{scheme}://{domain}/{line.lstrip('/')}"
    display_text = f"{line} → {absolute_url}"
    return display_text, absolute_url


def run_analysis_on_files(downloaded_info):
    domain_data = {}

    for js_path, domain, original_url, scheme in downloaded_info:
        try:
            rel_path = os.path.relpath(js_path, start=WORK_DIR)

            if domain not in domain_data:
                domain_data[domain] = {}
            if rel_path not in domain_data[domain]:
                domain_data[domain][rel_path] = {
                    'jsluice': [],      # (display_text, absolute_url)
                    'secretfinder': []
                }

            # === jsluice (NDJSON output) ===
            print(f"[→] jsluice: {js_path}")
            jsluice_result = subprocess.run(
                [JSLUICE_EXEC, "urls", js_path],
                capture_output=True,
                text=True,
                check=False
            )
            if jsluice_result.returncode == 0:
                url_groups = {}  # clean_base_url -> list of method info

                for line in jsluice_result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        raw_url = item.get("url", "").strip()
                        if not raw_url:
                            continue

                        clean_url = raw_url.replace("EXPR", "")

                        if "?" in clean_url:
                            path_part, query_part = clean_url.split("?", 1)
                        else:
                            path_part, query_part = clean_url, ""

                        while "//" in path_part:
                            path_part = path_part.replace("//", "/")
                        if not path_part.startswith("/") and not path_part.startswith(("javascript:", "#", "//", "mailto:", "tel:", "data:", "about:", "http")):
                            path_part = "/" + path_part

                        query_params_clean = []
                        if query_part:
                            for param in query_part.split("&"):
                                if "=" in param:
                                    key, _ = param.split("=", 1)
                                    if key and key not in query_params_clean:
                                        query_params_clean.append(key)
                                elif param:
                                    if param not in query_params_clean:
                                        query_params_clean.append(param)

                        if query_params_clean:
                            clean_query = "&".join([f"{p}={{{p}}}" for p in query_params_clean])
                            clean_base_url = f"{path_part}?{clean_query}"
                        else:
                            clean_base_url = path_part

                        if clean_base_url == "/":
                            continue

                        method = (item.get("method") or "GET").upper()
                        body_params = item.get("bodyParams", [])
                        url_type = item.get("type", "unknown")

                        if clean_base_url not in url_groups:
                            url_groups[clean_base_url] = []
                        url_groups[clean_base_url].append({
                            'method': method,
                            'type': url_type,
                            'query_params': query_params_clean,
                            'body_params': body_params
                        })

                    except json.JSONDecodeError:
                        continue

                # Преобразуем в формат для отчёта
                for clean_base_url, methods in url_groups.items():
                    base_for_absolute = clean_base_url.split("?")[0]
                    _, absolute_url = process_endpoint(base_for_absolute, domain, scheme)

                    # Используем множество для дедупликации строк методов
                    method_lines_set = set()
                    for m in methods:
                        parts = [m['method'], f"type: {m['type']}"]
                        if m['query_params']:
                            parts.append(f"query: {', '.join(sorted(m['query_params']))}")
                        if m['body_params']:
                            parts.append(f"body: {', '.join(sorted(m['body_params']))}")
                        method_line = " | ".join(parts)
                        method_lines_set.add(method_line)

                    # Сортируем для стабильного порядка
                    method_lines = sorted(method_lines_set)

                    if not method_lines:
                        continue

                    display_text = clean_base_url + "\n" + "\n".join(f"  • {line}" for line in method_lines)
                    domain_data[domain][rel_path]['jsluice'].append((display_text, absolute_url))

            else:
                print(f"    ⚠️ jsluice ошибка для {js_path}")
                if jsluice_result.stderr:
                    print(f"    stderr: {jsluice_result.stderr[:200]}")

            # === SecretFinder ===
            print(f"[→] SecretFinder: {js_path}")
            sf_result = subprocess.run(
                [PYTHON_EXEC, SECRET_FINDER_PY, '-i', js_path, '-o', 'cli'],
                capture_output=True,
                text=True,
                check=False
            )
            if sf_result.returncode == 0:
                for line in sf_result.stdout.strip().split('\n'):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith("[ + ] URL:"):
                        continue
                    domain_data[domain][rel_path]['secretfinder'].append(stripped)
            else:
                print(f"    ⚠️ SecretFinder ошибка для {js_path}")
                if sf_result.stderr:
                    print(f"    stderr: {sf_result.stderr[:200]}")

        except FileNotFoundError as e:
            print(f"[-] Не найден инструмент: {e}")
            exit(1)
        except Exception as e:
            print(f"[-] Ошибка при анализе {js_path}: {e}")

    # Генерация отчётов
    report_paths = []
    for domain, js_files in domain_data.items():
        html_content = generate_html_report(domain, js_files)
        safe_domain = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in domain)
        report_path = os.path.join(REPORTS_DIR, f"js_analysis_{safe_domain}.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        report_paths.append(os.path.abspath(report_path))
        print(f"[+] Отчёт сохранён: {report_path}")

    return report_paths


def generate_html_report(domain, js_files):
    total_jsluice = sum(len(data['jsluice']) for data in js_files.values())
    total_sf = sum(len(data['secretfinder']) for data in js_files.values())

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>JS Analysis Report - {domain}</title>
    <style>
        body {{ 
            font-family: Consolas, monospace; 
            margin: 20px; 
            background: #fdfdfd; 
            color: #333;
        }}
        h1 {{ color: #1976d2; }}
        h2 {{ color: #388e3c; margin-top: 30px; }}
        .file-header {{ 
            background: #e3f2fd; 
            padding: 10px; 
            border-left: 4px solid #2196f3; 
            margin: 15px 0; 
            border-radius: 4px;
            font-weight: bold;
        }}
        .line {{ margin: 6px 0; }}
        .line a {{ color: #d32f2f; text-decoration: none; }}
        .line a:hover {{ text-decoration: underline; }}
        .secret {{ 
            background: #fff8e1; 
            padding: 4px 8px; 
            border-left: 3px solid #ffc107; 
            margin: 4px 0;
            font-family: monospace;
            white-space: pre-wrap;
        }}
        .no-data {{ color: #666; font-style: italic; padding-left: 10px; }}
        .total {{ font-weight: bold; color: #1976d2; }}
        .section {{ margin-bottom: 40px; }}
        .methods {{
            background: #f9f9f9;
            padding: 8px 12px;
            border-radius: 4px;
            margin: 4px 0 12px 20px;
            font-size: 0.95em;
            color: #444;
            line-height: 1.4;
            white-space: pre;
            font-family: Consolas, monospace;
        }}
    </style>
</head>
<body>
    <h1>JS Analysis Report - <span style="color:#d32f2f">{domain}</span></h1>
    <p class="total">jsluice: {total_jsluice} endpoint(s) | SecretFinder: {total_sf} secret(s)</p>
"""

    # === jsluice Section ===
    html += '\n    <div class="section"><h2>🔍 jsluice Results</h2>'
    for js_file, data in js_files.items():
        pairs = data['jsluice']
        html += f'\n    <div class="file-header">Источник: {js_file}</div>\n'
        if pairs:
            for display, href in pairs:
                safe_display = (display
                                .replace('&', '&amp;')
                                .replace('<', '<')
                                .replace('>', '>')
                                .replace('"', '&quot;'))
                safe_href = href.replace('"', '&quot;').replace('<', '<').replace('>', '>')
                lines = safe_display.split('\n', 1)
                url_line = lines[0]
                methods_part = lines[1] if len(lines) > 1 else ""
                html += f'    <div class="line"><a href="{safe_href}" target="_blank">{url_line}</a></div>\n'
                if methods_part:
                    html += f'    <pre class="methods">{methods_part}</pre>\n'
        else:
            html += '    <div class="no-data">Нет endpoint' + 'ов' + '.</div>\n'
    html += '    </div>'

    # === SecretFinder Section ===
    html += '\n    <div class="section"><h2>🔑 SecretFinder Results</h2>'
    has_secrets = any(data['secretfinder'] for data in js_files.values())
    if not has_secrets:
        html += '    <div class="no-data">Нет найденных секретов.</div>\n'
    else:
        for js_file, data in js_files.items():
            secrets = data['secretfinder']
            if secrets:
                html += f'\n    <div class="file-header">Источник: {js_file}</div>\n'
                for secret in secrets:
                    safe_secret = (secret
                                   .replace('&', '&amp;')
                                   .replace('<', '<')
                                   .replace('>', '>'))
                    html += f'    <div class="secret">{safe_secret}</div>\n'
    html += '    </div>'

    html += """</body>
</html>"""
    return html


def main():
    parser = argparse.ArgumentParser(
        description="Скачивает JS-файлы, анализирует через jsluice и SecretFinder."
    )
    parser.add_argument("input_file", help="Путь к файлу со списком URL JS-файлов (внутри /work)")
    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[-] Файл {args.input_file} не найден.")
        return

    print("[*] Шаг 1: Скачивание JS-файлов...")
    downloaded_info = download_js_files(args.input_file)

    if not downloaded_info:
        print("[-] Нет файлов для анализа.")
        return

    print(f"\n[*] Шаг 2: Анализ через jsluice и SecretFinder...")
    report_paths = run_analysis_on_files(downloaded_info)

    if report_paths:
        print("\n[+] Отчёты сохранены в:")
        for path in report_paths:
            print(f"  → {path}")
    else:
        print("\n[!] Отчёты не созданы.")


if __name__ == "__main__":
    main()
