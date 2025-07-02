import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from scapy.all import AsyncSniffer, Ether, IP, TCP, UDP
import psutil
import matplotlib.pyplot as plt
from collections import Counter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter

def parse_packet(packet):
    parsed_data = {}
    if Ether in packet:
        parsed_data["Source MAC"] = packet[Ether].src
        parsed_data["Destination MAC"] = packet[Ether].dst
    if IP in packet:
        parsed_data["Source IP"] = packet[IP].src
        parsed_data["Destination IP"] = packet[IP].dst
        parsed_data["Protocol"] = packet[IP].proto
    if TCP in packet:
        parsed_data["Source Port"] = packet[TCP].sport
        parsed_data["Destination Port"] = packet[TCP].dport
    elif UDP in packet:
        parsed_data["Source Port"] = packet[UDP].sport
        parsed_data["Destination Port"] = packet[UDP].dport
    return parsed_data

def get_interfaces_with_names():
    interfaces = psutil.net_if_addrs()
    return {iface: iface for iface in interfaces}

class PacketSniffer:
    def __init__(self, gui):
        self.gui = gui
        self.sniffer = None

    def start(self, interface):
        self.sniffer = AsyncSniffer(iface=interface, prn=self.process_packet)
        self.sniffer.start()

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return
        parsed_data = parse_packet(packet)
        if parsed_data:
            self.gui.display_packet(packet, parsed_data)

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.sniffer = PacketSniffer(self)
        self.packets = []

        self.root.title("Packet Sniffer")
        self.root.geometry("1000x700")

        self.interface_frame = ttk.Frame(self.root)
        self.interface_frame.pack(fill=tk.X, pady=5)

        self.interface_label = ttk.Label(self.interface_frame, text="Select Interface:")
        self.interface_label.pack(side=tk.LEFT, padx=5)

        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(self.interface_frame, textvariable=self.interface_var, state="readonly")
        interfaces = get_interfaces_with_names()
        self.interface_menu['values'] = list(interfaces.values())
        self.interface_mapping = interfaces
        self.interface_menu.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(self.interface_frame, text="Start Capture", command=self.start_sniffer)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.interface_frame, text="Stop Capture", command=self.stop_sniffer)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.search_frame = ttk.Frame(self.root)
        self.search_frame.pack(fill=tk.X, pady=5)

        self.search_label = ttk.Label(self.search_frame, text="Search:")
        self.search_label.pack(side=tk.LEFT, padx=5)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.search_frame, textvariable=self.search_var, width=50)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        self.search_button = ttk.Button(self.search_frame, text="Search", command=self.search_packets)
        self.search_button.pack(side=tk.LEFT, padx=5)

        self.stats_button = ttk.Button(self.search_frame, text="Show Stats", command=self.show_stats)
        self.stats_button.pack(side=tk.LEFT, padx=5)

        self.graph_button = ttk.Button(self.search_frame, text="Show Graph", command=self.show_graph)
        self.graph_button.pack(side=tk.LEFT, padx=5)

        self.table_frame = ttk.Frame(self.root)
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            self.table_frame,
            columns=("Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"),
            show='headings'
        )
        self.tree.heading("Source IP", text="Source IP")
        self.tree.heading("Destination IP", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Source Port", text="Source Port")
        self.tree.heading("Destination Port", text="Destination Port")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.details_frame = ttk.LabelFrame(self.root, text="Packet Details")
        self.details_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.packet_details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, height=10)
        self.packet_details_text.pack(fill=tk.BOTH, expand=True)
        self.filtered_packets=None
        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)

    def start_sniffer(self):
        selected_interface_name = self.interface_var.get()
        if not selected_interface_name:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        selected_interface = next(
            (key for key, value in self.interface_mapping.items() if value == selected_interface_name), None
        )

        if not selected_interface:
            messagebox.showerror("Error", "Invalid interface selection.")
            return

        self.packets = []
        self.tree.delete(*self.tree.get_children())
        self.sniffer.start(selected_interface)

    def stop_sniffer(self):
        self.sniffer.stop()
        messagebox.showinfo("Info", "Packet capture stopped.")

    def display_packet(self, packet, parsed_data):
        if not any(parsed_data.values()):
            return
        self.packets.append((packet, parsed_data))
        self.tree.insert(
            "",
            tk.END,
            values=(
                parsed_data.get("Source IP", "N/A"),
                parsed_data.get("Destination IP", "N/A"),
                parsed_data.get("Protocol", "N/A"),
                parsed_data.get("Source Port", "N/A"),
                parsed_data.get("Destination Port", "N/A"),
            ),
        )

    def show_packet_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        item_index = self.tree.index(selected_item[0])

        packets_to_use = self.filtered_packets if self.filtered_packets is not None else self.packets

        if 0 <= item_index < len(packets_to_use):
            full_packet, _ = packets_to_use[item_index]
            self.packet_details_text.delete("1.0", tk.END)
            self.packet_details_text.insert(tk.END, full_packet.show(dump=True))


    def show_stats(self):
        packets_to_use = self.filtered_packets if self.filtered_packets is not None else self.packets

        protocol_count = {}
        src_ip_count = {}
        dst_ip_count = {}
        port_count = {}

        for _, parsed_data in packets_to_use:
            protocol = parsed_data.get("Protocol", "N/A")
            src_ip = parsed_data.get("Source IP", "N/A")
            dst_ip = parsed_data.get("Destination IP", "N/A")
            src_port = parsed_data.get("Source Port", "N/A")
            dst_port = parsed_data.get("Destination Port", "N/A")

            protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
            src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1
            dst_ip_count[dst_ip] = dst_ip_count.get(dst_ip, 0) + 1
            port_count[src_port] = port_count.get(src_port, 0) + 1
            port_count[dst_port] = port_count.get(dst_port, 0) + 1

        protocol_count = {k: v for k, v in sorted(protocol_count.items(), key=lambda item: item[1], reverse=True)}
        src_ip_count = {k: v for k, v in sorted(src_ip_count.items(), key=lambda item: item[1], reverse=True)}
        dst_ip_count = {k: v for k, v in sorted(dst_ip_count.items(), key=lambda item: item[1], reverse=True)}
        port_count = {k: v for k, v in sorted(port_count.items(), key=lambda item: item[1], reverse=True)}

        stats = "Protocols:\n" + "\n".join([f"{k:<20} {v}" for k, v in protocol_count.items()])
        stats += "\n\nSource IPs:\n" + "\n".join([f"{k:<20} {v}" for k, v in src_ip_count.items()])
        stats += "\n\nDestination IPs:\n" + "\n".join([f"{k:<20} {v}" for k, v in dst_ip_count.items()])
        stats += "\n\nPorts:\n" + "\n".join([f"{k:<20} {v}" for k, v in port_count.items()])

        stats_window = tk.Toplevel(self.root)
        stats_window.title("Packet Stats")
        stats_window.geometry("600x400")

        stats_text = scrolledtext.ScrolledText(stats_window, wrap=tk.WORD)
        stats_text.pack(fill=tk.BOTH, expand=True)
        stats_text.insert(tk.END, stats)
        stats_text.config(state=tk.DISABLED)

    def show_graph(self):
        timestamps = [packet.time for packet, _ in self.packets]
        if not timestamps:
            messagebox.showinfo("Info", "No packets captured to display the graph.")
            return

        intervals = [int(ts) for ts in timestamps]
        counts = Counter(intervals)
        times = sorted(counts.keys())
        packet_counts = [counts[time] for time in times]

        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(times, packet_counts, label="Packets over Time", color="blue", linewidth=2)

        ax.set_title("Packet Traffic Over Time")
        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Packet Count")
        ax.legend()
        ax.grid()

        graph_window = tk.Toplevel(self.root)
        graph_window.title("Real-Time Packet Graph")
        graph_window.geometry("1200x600")

        canvas_frame = ttk.Frame(graph_window)
        canvas_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(canvas_frame)
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=canvas.xview)
        canvas.configure(xscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        figure_canvas = FigureCanvasTkAgg(fig, canvas)
        figure_canvas.draw()
        figure_widget = figure_canvas.get_tk_widget()
        figure_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        def configure_canvas(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        canvas.create_window((0, 0), window=figure_widget, anchor="nw")
        figure_widget.bind("<Configure>", configure_canvas)

    def search_packets(self):
        query = self.search_var.get().strip()

        if not query:
            self.tree.delete(*self.tree.get_children())
            self.filtered_packets = None
            for packet, parsed_data in self.packets:
                self.display_packet(packet, parsed_data)
            return

        conditions = [condition.strip().lower() for condition in query.split(" ")]

        if not conditions:
            messagebox.showinfo("Search Results", "Invalid search query.")
            return

        results = self.filter_packets(conditions)

        self.tree.delete(*self.tree.get_children())
        if not results:
            messagebox.showinfo("Search Results", "No matching packets found.")
        else:
            for packet, parsed_data in results:
                self.display_packet(packet, parsed_data)


    def search_packets(self):
        query = self.search_var.get().strip()
        self.tree.delete(*self.tree.get_children())

        if not query:
            packets_to_display = self.packets 
            self.filtered_packets = None  
        else:
            packets_to_display = self.filter_packets(query.lower().split())
            self.filtered_packets = packets_to_display

            if not packets_to_display:
                messagebox.showinfo("Search Results", "No matching packets found.")
                return

        self._populate_tree(packets_to_display)

    
    def _populate_tree(self, packets):
        def batch_insert(start):
            end = min(start + 100, len(packets)) 
            for packet, parsed_data in packets[start:end]:
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        parsed_data.get("Source IP", "N/A"),
                        parsed_data.get("Destination IP", "N/A"),
                        parsed_data.get("Protocol", "N/A"),
                        parsed_data.get("Source Port", "N/A"),
                        parsed_data.get("Destination Port", "N/A"),
                    ),
                )
            if end < len(packets): 
                self.root.after(10, batch_insert, end)

        batch_insert(0) 



    def filter_packets(self, conditions):
        results = []
        for packet, parsed_data in self.packets:
            parsed_values = {k.lower(): str(v).lower() for k, v in parsed_data.items()}

            if "and" in conditions:
                if all(
                    any(condition in v for v in parsed_values.values())
                    for condition in conditions if condition != "and"
                ):
                    results.append((packet, parsed_data))
            else:
                if any(
                    condition in v
                    for v in parsed_values.values()
                    for condition in conditions if condition != "or"
                ):
                    results.append((packet, parsed_data))
        return results



if __name__ == "__main__":
    root = tk.Tk()
    gui = SnifferGUI(root)
    root.mainloop()
