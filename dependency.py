import menu
import subprocess
import sys
import time


def dependency_check():
    tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "macchanger", "iwconfig"]

    print(f"\n{menu.B}[ DEPENDENCY CHECK ]{menu.X}")
    print("-" * 40)

    missing = []
    for tool in tools:
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode == 0:
            print(f"  {menu.G}[OK]{menu.X}    {tool}")
        else:
            print(f"  {menu.R}[MISSING]{menu.X}  {tool}")
            missing.append(tool)

        time.sleep(1)

    print("─" * 40)

