import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import datetime
import time
import ctypes
import sys

from scapy.config import conf
conf.L2socket = conf.L3socket  # Force Scapy to use Layer 3 (No Npcap/WinPcap needed)


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Packet Analyzer (Wireshark-lite)")

        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill="both", expand=True)

        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.pack(side="left", fill="y", padx=10, pady=10)

        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        ttk.Label(self.left_frame, text="Protocol Filter:").pack(pady=(0, 5))
        self.protocol_var = tk.StringVar(value="All")
        self.protocol_menu = ttk.Combobox(self.left_frame, textvariable=self.protocol_var, state="readonly")
        self.protocol_menu['values'] = ("All", "TCP", "UDP", "ICMP")
        self.protocol_menu.pack(pady=5, fill="x")

        self.start_button = ttk.Button(self.left_frame, text="▶ Start Capture", command=self.start_sniffing)
        self.start_button.pack(pady=5, fill="x")

        self.stop_button = ttk.Button(self.left_frame, text="■ Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5, fill="x")

        self.save_button = ttk.Button(self.left_frame, text="💾 Save to File", command=self.save_to_file, state=tk.DISABLED)
        self.save_button.pack(pady=5, fill="x")

        self.animation_label = tk.Label(self.left_frame, text="", font=("Consolas", 10, "italic"), fg="green")
        self.animation_label.pack(pady=(10, 5))

        self.dark_mode_var = tk.BooleanVar(value=False)
        self.dark_mode_check = ttk.Checkbutton(self.left_frame, text="🌙 Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode)
        self.dark_mode_check.pack(pady=(10, 5))

        self.stats_label = tk.Label(self.right_frame, text="Stats: Packets=0 | PPS=0 | TCP=0 | UDP=0 | ICMP=0 | OTHER=0",
                                    font=("Consolas", 10), fg='blue')
        self.stats_label.pack(anchor='w', pady=(0, 5))

        self.output_box = scrolledtext.ScrolledText(self.right_frame, width=100, height=30, bg='black', fg='lime')
        self.output_box.pack(fill="both", expand=True)

        self.running = False
        self.packet_logs = []

        self.total_packets = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        self.last_time = time.time()
        self.last_count = 0

        self.animation_index = 0
        self.animation_texts = ["Capturing", "Capturing.", "Capturing..", "Capturing..."]

    def start_sniffing(self):
        self.running = True
        self.packet_logs.clear()
        self.output_box.delete('1.0', tk.END)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)

        self.total_packets = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        self.last_time = time.time()
        self.last_count = 0

        self.animation_label.config(text="Capturing...")
        threading.Thread(target=self.sniff_packets, daemon=True).start()
        self.update_stats_loop()
        self.animate_capturing()

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.animation_label.config(text="Stopped Capturing")

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=0, stop_filter=lambda x: not self.running)

    def process_packet(self, packet):
        if IP in packet:
            selected_proto = self.protocol_var.get()
            if selected_proto == "TCP" and not packet.haslayer(TCP): return
            elif selected_proto == "UDP" and not packet.haslayer(UDP): return
            elif selected_proto == "ICMP" and not packet.haslayer(ICMP): return

            proto = "OTHER"
            sport = dport = "-"
            if packet.haslayer(TCP):
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                self.tcp_count += 1
            elif packet.haslayer(UDP):
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                self.udp_count += 1
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                self.icmp_count += 1
            else:
                self.other_count += 1

            self.total_packets += 1
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            info = f"[{timestamp}] {packet[IP].src}:{sport} -> {packet[IP].dst}:{dport} | {proto}"
            self.output_box.insert(tk.END, info + "\n")
            self.output_box.see(tk.END)
            self.packet_logs.append(info)

    def update_stats_loop(self):
        if not self.running:
            return
        current_time = time.time()
        elapsed = current_time - self.last_time
        pps = self.total_packets - self.last_count if elapsed >= 1.0 else 0
        if elapsed >= 1.0:
            self.last_count = self.total_packets
            self.last_time = current_time
        self.stats_label.config(text=f"Stats: Packets={self.total_packets} | PPS={pps} | "
                                     f"TCP={self.tcp_count} | UDP={self.udp_count} | ICMP={self.icmp_count} | OTHER={self.other_count}")
        self.root.after(1000, self.update_stats_loop)

    def animate_capturing(self):
        if not self.running:
            return
        self.animation_label.config(text=self.animation_texts[self.animation_index])
        self.animation_index = (self.animation_index + 1) % len(self.animation_texts)
        self.root.after(500, self.animate_capturing)

    def save_to_file(self):
        if not self.packet_logs:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt")],
                                                 title="Save Packet Log As")
        if file_path:
            with open(file_path, 'w') as f:
                f.write("\n".join(self.packet_logs))
            messagebox.showinfo("Success", f"Packet data saved to {file_path}")

    def toggle_dark_mode(self):
        dark = self.dark_mode_var.get()
        bg_color = "#1e1e1e" if dark else "white"
        fg_color = "lime" if dark else "black"
        text_bg = "#000000" if dark else "white"
        text_fg = "lime" if dark else "black"

        self.output_box.config(bg=text_bg, fg=text_fg, insertbackground=text_fg)
        self.right_frame.config(style='Dark.TFrame' if dark else 'TFrame')
        self.left_frame.config(style='Dark.TFrame' if dark else 'TFrame')

        style = ttk.Style()
        style.configure("Dark.TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TButton", background=bg_color, foreground=fg_color)
        style.configure("TCheckbutton", background=bg_color, foreground=fg_color)


def is_admin():
    """Check if script is running as admin (Windows only)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":
    if sys.platform == "win32" and not is_admin():
        messagebox.showwarning("Permission Required", "Please run this program as administrator for packet sniffing to work.")
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
