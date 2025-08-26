import fake_ap
import threading
import captive_portal as cp

def main():
    cp.captive_portal("192.168.0.1")
    

if __name__ == '__main__':
    main()