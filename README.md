# Aeropwn

A Wi-Fi penetration testing automation tool built around the **aircrack-ng** suite. Designed for authorized security assessments and educational purposes.

---

## Legal Disclaimer

> **Aeropwn is intended exclusively for authorized penetration testing and security research.**
>
> Using this tool against any network or device **without explicit written permission** from the owner is **illegal** and may result in criminal prosecution under applicable laws (e.g. Computer Fraud and Abuse Act, Computer Misuse Act, or equivalent legislation in your jurisdiction).
>
> The author assumes **no liability** for any misuse, damage, or legal consequences arising from the use of this tool. You are solely responsible for your actions.
>
> **Only use this tool on networks and devices you own or have explicit written authorization to test.**

---

## Features

- **Automated WPA/WPA2 handshake capture** — scan nearby networks, select targets, and capture handshakes via deauthentication attacks
- **MAC address spoofing** — randomize the MAC address of a selected interface using `macchanger`
- **Batch attack mode** — attack multiple networks in sequence, skipping those where a handshake was already captured
- **Interactive menu** — clean terminal UI with color output

---

## Requirements

- Linux (tested on Kali Linux)
- Python 3.x
- The following tools must be installed and accessible via `sudo`:
  - `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`)
  - `macchanger`
  - `iwconfig`

### Install dependencies (Debian/Kali)

```bash
sudo apt update
sudo apt install aircrack-ng macchanger wireless-tools
```

---

## Installation

```bash
git clone https://github.com/yourusername/aeropwn.git
cd aeropwn
```

No additional Python packages are required — only standard library modules are used.

---

## Usage

```bash
sudo python3 main.py
```

> Root privileges (`sudo`) are required for interface management and packet injection.

### Menu options

| Option | Description |
|--------|-------------|
| `1` | **Start Attack** — select interface, scan for networks, capture WPA handshakes |
| `2` | **MAC Spoofing** — randomize the MAC address of a selected interface |
| `0` | **Exit** |

### Attack workflow

1. Select or confirm your wireless interface
2. Optionally switch the interface to monitor mode
3. Set scan duration — `airodump-ng` will discover nearby networks
4. Select target networks by number (or `all`)
5. Set attack duration per network
6. Aeropwn runs `airodump-ng` + `aireplay-ng` (continuous deauth) simultaneously
7. After each attack, `aircrack-ng` verifies whether a handshake was captured
8. Captured `.cap` files are kept in the working directory for offline cracking

---

## Output files

| File | Description |
|------|-------------|
| `capture_<SSID>-01.cap` | Captured WPA handshake (kept after successful capture) |
| `networks_in_range.json` | Temporary list of discovered networks (auto-generated, not committed) |

---

## Notes

- The tool skips networks with hidden SSIDs during scanning
- Networks where a handshake was already captured are skipped in subsequent attack loop iterations
- Auxiliary airodump files (`.csv`, `.kismet.csv`, `.kismet.netxml`, `.log.csv`) are automatically removed after each attack

---

## License

MIT License — see [LICENSE](LICENSE) for details.
