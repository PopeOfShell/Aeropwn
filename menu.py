import os


#===================
#======COLORS=======
#===================
R = "\033[91m"   # red
G = "\033[92m"   # green
Y = "\033[93m"   # yellow
C = "\033[96m"   # cyan
W = "\033[97m"   # white
B = "\033[1m"    # bold
X = "\033[0m"    # reset

def banner(macchanger_switch):
    os.system("clear")
    print(r""" ______     ______     ______     ______     ______   __     __     __   __    
/\  __ \   /\  ___\   /\  == \   /\  __ \   /\  == \ /\ \  _ \ \   /\ "-.\ \   
\ \  __ \  \ \  __\   \ \  __<   \ \ \/\ \  \ \  _-/ \ \ \/ ".\ \  \ \ \-.  \  
 \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\    \ \__/".~\_\  \ \_\\"\_\ 
  \/_/\/_/   \/_____/   \/_/ /_/   \/_____/   \/_/     \/_/   \/_/   \/_/ \/_/ 
                                                                               """)
    print(f"{X}", end="")

    if macchanger_switch == True:
        print(f"{R}MAC Spoofing ON [x]{X}")





def menu():
    banner(macchanger_switch)
    print(f"{Y}[1]{X} Start Attack")
    print(f"{Y}[2]{X} MAC Spoofing")
    print(f"{Y}[0]{X} Exit")
    select = input("\n> ").strip()
    return int(select)