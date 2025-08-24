import fake_ap
import threading
import captive_portal as cp

def main():
    fake_ap.create_fake_ap("Test", 11, "wlan0", "192.168.0.1", "192.168.0.2")
    

if __name__ == '__main__':
    main()