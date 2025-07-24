import telebot
import requests
import pandas as pd
from ratelimit import limits, sleep_and_retry
import os
import logging
import json

# Đọc config từ file configs.json
with open('configs.json', 'r', encoding='utf-8') as f:
    configs = json.load(f)
TELEGRAM_TOKEN = configs['TELEGRAM_TOKEN']
WHOISFREAKS_API_KEY = configs['WHOISFREAKS_API_KEY']

# Thiết lập logging cho API call
logging.basicConfig(
    filename='whois_api.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

bot = telebot.TeleBot(TELEGRAM_TOKEN)

CALLS = 50
RATE_LIMIT_PERIOD = 60  # giây

@sleep_and_retry
@limits(calls=CALLS, period=RATE_LIMIT_PERIOD)
def get_historical_whois(domain):
    url = "https://api.whoisfreaks.com/v1.0/whois"
    params = {
        "apiKey": WHOISFREAKS_API_KEY,
        "whois": "historical",
        "domainName": domain
    }
    response = requests.get(url, params=params)
    # Ghi log API call
    logging.info(f"API CALL | domain: {domain} | status: {response.status_code} | response: {response.text}")
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"API error: {response.status_code} - {response.text}"}

@bot.message_handler(content_types=['document'])
def handle_file(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)
    file_name = message.document.file_name
    temp_path = f'tmp_{file_name}'
    with open(temp_path, 'wb') as new_file:
        new_file.write(downloaded_file)

    # Đọc danh sách domain
    with open(temp_path, 'r', encoding='utf-8') as f:
        domains = [line.strip() for line in f if line.strip()]

    bot.reply_to(message, f"Đang tra cứu {len(domains)} domain, vui lòng chờ...")

    # Gom kết quả theo từng domain
    domain_dict = {}
    for domain in domains:
        data = get_historical_whois(domain)
        records = data.get("whois_domains_historical", [])
        if "error" in data or not records:
            domain_dict[domain] = {
                "nameservers": [],
                "registrants": [],
                "statuses": []
            }
            continue

        ns_set = []
        reg_set = []
        status_set = []
        for rec in records:
            # Nameservers (list)
            ns = rec.get("name_servers", [])
            for n in ns:
                if n not in ns_set:
                    ns_set.append(n)
            # Registrant (string)
            registrant = rec.get("registrant_contact", {}).get("name", "") if rec.get("registrant_contact") else ""
            if registrant and registrant not in reg_set:
                reg_set.append(registrant)
            # Status (list)
            statuses = rec.get("domain_status", [])
            for s in statuses:
                if s not in status_set:
                    status_set.append(s)
        domain_dict[domain] = {
            "nameservers": ns_set,
            "registrants": reg_set,
            "statuses": status_set
        }

    # Xuất file theo định dạng yêu cầu
    output_file = f"whois_results_{message.chat.id}.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for domain, info in domain_dict.items():
            ns_str = ",".join(info["nameservers"]) if info["nameservers"] else ""
            reg_str = ",".join(info["registrants"]) if info["registrants"] else ""
            status_str = ",".join(info["statuses"]) if info["statuses"] else ""
            f.write(f"{domain}|{ns_str}|{reg_str}|{status_str}\n")

    with open(output_file, "rb") as result_file:
        bot.send_document(message.chat.id, result_file, caption="Kết quả tra cứu WHOIS")

    # Xóa file tạm
    os.remove(temp_path)
    os.remove(output_file)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Gửi file .txt hoặc .csv (mỗi dòng 1 domain) để tra cứu lịch sử WHOIS.")

if __name__ == "__main__":
    print("Bot đang chạy...")
    bot.remove_webhook()
    bot.polling(none_stop=True) 