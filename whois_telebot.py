import telebot
import requests
import pandas as pd
import os
import logging
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from threading import Semaphore

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

# Rate limit control - 50 requests per minute
RATE_LIMIT_CALLS = 50
RATE_LIMIT_PERIOD = 60  # seconds
rate_limit_semaphore = Semaphore(RATE_LIMIT_CALLS)
last_request_time = 0
request_lock = threading.Lock()

def get_historical_whois(domain):
    global last_request_time
    
    # Kiểm soát rate limit
    with request_lock:
        current_time = time.time()
        time_since_last = current_time - last_request_time
        min_interval = RATE_LIMIT_PERIOD / RATE_LIMIT_CALLS  # 1.2 seconds between requests
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)
        
        last_request_time = time.time()
    
    url = "https://api.whoisfreaks.com/v1.0/whois"
    params = {
        "apiKey": WHOISFREAKS_API_KEY,
        "whois": "historical",
        "domainName": domain
    }
    response = requests.get(url, params=params)
    # Ghi log API call
    logging.info(f"API CALL | domain: {domain} | status: {response.status_code}")
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"HTTP {response.status_code}"}

def process_domain(domain):
    """Xử lý một domain và trả về kết quả"""
    try:
        data = get_historical_whois(domain)
        records = data.get("whois_domains_historical", [])
        
        if "error" in data or not records:
            return domain, {
                "historical": []
            }

        # Gom nhóm theo registrar
        registrar_groups = {}
        
        for rec in records:
            registrar_name = rec.get("domain_registrar", {}).get("registrar_name", "") if rec.get("domain_registrar") else ""
            
            if registrar_name not in registrar_groups:
                registrar_groups[registrar_name] = {
                    "registrars": registrar_name,
                    "nameservers": set(),
                    "status": set(),
                    "created_dates": set(),
                    "expired_dates": set()
                }
            
            # Thêm nameservers
            nameservers = rec.get("name_servers", [])
            for ns in nameservers:
                registrar_groups[registrar_name]["nameservers"].add(ns)
            
            # Thêm status
            statuses = rec.get("domain_status", [])
            for status in statuses:
                registrar_groups[registrar_name]["status"].add(status)
            
            # Thêm dates
            created_date = rec.get("create_date", "")
            if created_date:
                registrar_groups[registrar_name]["created_dates"].add(created_date)
            
            expired_date = rec.get("expiry_date", "")
            if expired_date:
                registrar_groups[registrar_name]["expired_dates"].add(expired_date)
        
        # Chuyển đổi sets thành lists và tạo historical data
        historical_data = []
        for registrar_name, group_data in registrar_groups.items():
            historical_record = {
                "registrars": group_data["registrars"],
                "nameservers": list(group_data["nameservers"]),
                "status": list(group_data["status"]),
                "created_date": list(group_data["created_dates"]),
                "expired_date": list(group_data["expired_dates"])
            }
            historical_data.append(historical_record)
                    
        return domain, {
            "historical": historical_data
        }
    except Exception as e:
        logging.error(f"Error processing domain {domain}: {str(e)}")
        return domain, {
            "historical": []
        }

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

    bot.reply_to(message, f"Đang tra cứu {len(domains)} domain với xử lý song song, vui lòng chờ...")

    # Xử lý song song các domain
    domain_dict = {}
    start_time = time.time()
    
    # Giảm số worker threads để tránh vượt quá rate limit
    # Với 50 requests/phút, mỗi request cần 1.2s, nên dùng 3-5 threads là phù hợp
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Gửi tất cả các task
        future_to_domain = {executor.submit(process_domain, domain): domain for domain in domains}
        
        # Xử lý kết quả khi hoàn thành
        completed = 0
        for future in as_completed(future_to_domain):
            domain, result = future.result()
            domain_dict[domain] = result
            completed += 1
            
            # Cập nhật tiến độ mỗi 10 domain
            if completed % 10 == 0:
                progress_msg = f"Đã xử lý {completed}/{len(domains)} domain..."
                try:
                    bot.edit_message_text(progress_msg, message.chat.id, message.message_id + 1)
                except:
                    pass

    end_time = time.time()
    processing_time = end_time - start_time
    
    logging.info(f"Completed processing {len(domains)} domains in {processing_time:.2f} seconds")

    # Tạo cấu trúc JSON theo yêu cầu
    json_result = []
    for domain, info in domain_dict.items():
        domain_data = {
            "domain": domain,
            "historical": info["historical"]
        }
        json_result.append(domain_data)

    # Xuất file JSON
    output_file = f"whois_results_{message.chat.id}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(json_result, f, indent=2, ensure_ascii=False)

    with open(output_file, "rb") as result_file:
        bot.send_document(message.chat.id, result_file, 
                         caption=f"Kết quả tra cứu WHOIS - {len(domains)} domain trong {processing_time:.2f}s")

    # Xóa file tạm
    os.remove(temp_path)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Gửi file .txt hoặc .csv (mỗi dòng 1 domain) để tra cứu lịch sử WHOIS.")

if __name__ == "__main__":
    print("Bot đang chạy...")
    bot.remove_webhook()
    bot.polling(none_stop=True) 