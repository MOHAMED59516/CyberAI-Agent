import tkinter as tk
from tkinter import ttk
import threading
import pandas as pd
from scapy.all import sniff, IP
from joblib import load
import subprocess
import os

MODEL_PATH = "ai_model.pkl"
LOG_PATH = "data/threats_log.csv"

try:
    model = load(MODEL_PATH)
    print("[INFO] تم تحميل الموديل بنجاح.")
except Exception as e:
    print(f"[ERROR] لم يتم تحميل الموديل: {e}")
    model = None

if not os.path.exists("data"):
    os.makedirs("data")

if not os.path.exists(LOG_PATH):
    pd.DataFrame(columns=["src_ip", "dst_ip", "prediction"]).to_csv(LOG_PATH, index=False)

def log_threat(src_ip, dst_ip, prediction):
    df = pd.read_csv(LOG_PATH)
    df = pd.concat([df, pd.DataFrame([[src_ip, dst_ip, prediction]], columns=["src_ip", "dst_ip", "prediction"])])
    df.to_csv(LOG_PATH, index=False)
    update_threats_table()

def block_ip(ip):
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}",
                        "dir=in", "action=block", f"remoteip={ip}"], check=True)
        print(f"[INFO] تم حظر IP {ip}")
    except subprocess.CalledProcessError:
        print(f"[ERROR] فشل في حظر {ip}")

def detect_attack(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        features = [len(packet), packet.ttl if hasattr(packet, 'ttl') else 0, packet.proto if hasattr(packet, 'proto') else 0]
        if model:
            prediction = model.predict([features])[0]
            if prediction == 1:
                log_threat(ip_src, ip_dst, prediction)
                block_ip(ip_src)
                update_status(f"[!] تهديد من {ip_src} تم حظره")

root = tk.Tk()
root.title("Cybersecurity Agent")
root.geometry("600x400")
status_text = tk.StringVar()
status_text.set("الحالة: غير نشط")

running = False

def start_agent():
    global running
    running = True
    status_text.set("الحالة: جاري المراقبة")
    threading.Thread(target=sniff_packets, daemon=True).start()

def stop_agent():
    global running
    running = False
    status_text.set("الحالة: متوقف")

def sniff_packets():
    sniff(prn=detect_attack, store=0, stop_filter=lambda x: not running)

def update_status(message):
    status_text.set(message)
    print(message)

def update_threats_table():
    for row in threats_table.get_children():
        threats_table.delete(row)
    if os.path.exists(LOG_PATH):
        df = pd.read_csv(LOG_PATH)
        for index, row in df.iterrows():
            threats_table.insert("", "end", values=(row["src_ip"], row["dst_ip"], row["prediction"]))

frame_top = tk.Frame(root)
frame_top.pack(pady=10)
start_btn = tk.Button(frame_top, text="ابدأ المراقبة", command=start_agent, bg="green", fg="white")
start_btn.grid(row=0, column=0, padx=5)
stop_btn = tk.Button(frame_top, text="أوقف المراقبة", command=stop_agent, bg="red", fg="white")
stop_btn.grid(row=0, column=1, padx=5)
status_label = tk.Label(root, textvariable=status_text, fg="blue")
status_label.pack(pady=5)

table_frame = tk.Frame(root)
table_frame.pack(pady=10, fill="both", expand=True)
columns = ("src_ip", "dst_ip", "prediction")
threats_table = ttk.Treeview(table_frame, columns=columns, show="headings")
for col in columns:
    threats_table.heading(col, text=col)
    threats_table.column(col, anchor="center")
threats_table.pack(fill="both", expand=True)

update_threats_table()

root.mainloop()
