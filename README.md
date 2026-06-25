**Passive Network Traffic Analyzer & IoT Vulnerability Profiler 📸**

Iris CamOracle is a specialized digital forensics and network auditing tool designed to passively analyze IoT camera network traffic. Developed as part of an academic thesis project, it parses PCAP (Packet Capture) files to profile device behavior, evaluate encryption standards, detect unencrypted protocol leaks, and trace outbound connections against global threat intelligence databases.

**Note:** This is a sister tool to Diana StreamSniffer.
While Diana is an active scanner that probes local networks for exposed ports and credentials, Iris is entirely passive. It relies strictly on pre-captured PCAP files to analyze behavior without sending a single packet to the target device.

**Features**
- Deep Packet Inspection (DPI): Accurately flags unencrypted video streams (RTP), auth-less RTSP, Outdated Telnet, cleartext FTP, and MQTT traffic without relying solely on standard port numbers.
- Granular TLS/Encryption Auditing: Performs deep extraction of TLS handshakes to grade the cryptographic health of the device:
  > - Evaluates TLS versions, mapping cipher suites to security grades (Strong/Adequate/Weak/Insecure).
  > - Extracts x509 certificates natively via ASN.1 binary decoding (bypassing fragile regex) to identify Private/Untrusted Certificate Authorities.
  > - Validates certificate lifespans and flags non-compliant "excessive lifespan" certificates typical in vulnerable supply chains.
- Threat Intelligence & OSINT Integration: Analyzes outbound connections (phone-home traffic) by cross-referencing external IPs against:
  > - Abuse.ch ThreatFox: Detects if the camera is communicating with known botnets or malware command-and-control (C2) servers.
  > - Shodan InternetDB: Checks external destination servers for known CVEs (Common Vulnerabilities and Exposures) and security tags.
  > - IP-API: Maps cross-border data flows to flag potential privacy jurisdiction risks.
- Traffic Scenario Profiling & Visualization: Groups traffic flow into six predefined behavioral scenarios (Startup, Idle, Motion, App Access, Live View, Motion Off) and automatically generates a Kibana-style histogram chart to visualize transmission frequency over time.

**Special?**
- IoT-Specific False Positive Reduction: Automatically suppresses standard TCP Reset (RST) noise and intelligently corrects protocol misattributions (e.g., identifying P2P video streams over port 6010 instead of mislabeling them as X11 SSH backdoors).
- Automated Threat Context: Translates raw packets into readable risk assessments, warning users about supply chain vulnerabilities or data sovereignty issues if a device silently streams telemetry to overseas servers.
- Built-in Visualizations: Automatically graphs traffic dynamics and saves a high-resolution .png histogram next to your PCAP, perfectly formatted for academic papers or audit reports.

**System Requirements 📝** 
- Python 3.12 (Developed and tested on this version)
- Wireshark / TShark (Must be installed on the host system OS for packet parsing to function)
Install required dependencies
pip install matplotlib
pip install pyshark
pip install requests
pip install tabulate
pip install cryptography

**🕹 How to Use:**
To get the most accurate results for the Traffic Frequency Analysis & Histogram, you must record the PCAP file in a controlled environment. The Iris histogram expects a 6-minute (360-second) capture window divided into specific behavioral scenarios.

▶️ Setup Preparation:
  1. Isolate the Network: Do not connect the camera directly to your home router. Instead, use a Laptop PC to broadcast a Mobile Hotspot and connect the IP Camera to this hotspot.
  2. Pre-configure the Camera: Ensure the camera's motion detection/alarm feature is turned ON via its companion app.
  3. Control the Environment: Face the camera toward a blank wall. Ensure there are no moving objects, shadows, or people in its field of view.
  4. Prepare the Sniffer: Open Wireshark on the laptop and select the Hotspot/virtual Wi-Fi interface.

The 6-Minute Recording Timeline:
  1. Unplug the camera. Start your Wireshark capture, and plug the camera's power back in. Start a stopwatch exactly when the first packet appears in Wireshark.
  Minute 0 to 1 (0s - 60s) — Scenario 1: Camera Startup Let the camera boot up and establish its initial handshakes with the vendor's cloud servers. Do nothing.
  
  2. Minute 1 to 2 (60s - 120s) — Scenario 2: Idle (Alarm On)
  Keep the environment completely still. This captures the baseline heartbeat/telemetry traffic.
  
  3. Minute 2 to 3 (120s - 180s) — Scenario 3: Motion (Alarm On)
  Walk in front of the camera or wave your hands continuously to trigger the motion sensors and force the camera to upload alarm clips/snapshots to the cloud.
  
  4. Minute 3 to 4 (180s - 240s) — Scenario 4: Accessing App
  Stop moving (return to a static environment). Open the camera's mobile app on your phone, but do not open the live video feed. Refresh the app's home screen a few times to capture API polling traffic.
  
  5. Minute 4 to 5 (240s - 300s) — Scenario 5: Live Camera View
  Tap into the camera's live video feed on your phone. This will capture the heavy UDP/TCP stream tunneling traffic.
  
  6. Minute 5 to 6 (300s - 360s) — Scenario 6: Motion (Alarm Off)
  Exit the live feed and use the app to turn OFF the motion alarm. Wave your hands in front of the camera again. This tests if the camera still secretly records or transmits motion data even when the user has explicitly disabled the feature.

After the 6-minute passive capture is complete, keep the camera running and execute the sister tool, Diana StreamSniffer, targeting the camera's IP. 
  - If Diana discovers an open RTSP port, try accessing the provided URL via VLC Media Player.
  - You can safely stop the Wireshark recording once the active scan is complete.
From that pcapng file, you can put it inside the Iris tool, dont forget the IP Address of the camera.


**Educational and Auditing Purposes Only ⚠️**
Iris CamOracle was created for an academic thesis project to demonstrate the prevalence of insecure communications, supply chain vulnerabilities, and excessive data collection in consumer IoT cameras.

The developer assumes no liability for misuse.
