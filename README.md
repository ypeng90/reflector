# Reflector

Reflect packets targeting at victim machine back to attacker, preventing victim machine from malicious attacks.

## How It Works

- Startup:
  - Parse and validate command line arguments for network interface of host machine, ip address and hardware address of victim machine.
  - Initialize libnet context, and get ip address and hardware of host.
  - Initialize libpcap packet capture handle, and set filter to capture all ARP,  and IPv4 ICMP, TCP and UDP packets targeting at victim machine.

- ARP Spoofing
  - Send ARP response packets periodically to broadcast victim machine is at host MAC.

- Capture Packets and Process
  - ARP request packets: send ARP replies packets to tell attacker that victim machine is at host MAC.
  - IPv4 ICMP, TCP and UDP packets: send packets with modified destination and recalculated checksums back to attacker.

- Cleanup:
  - Send ARP response packets to broadcast victim machine is at victim MAC.
  - Close libnet context and libpcap packet capture handle.

## Requirements

- `libnet`

  ```bash
  # for Ubuntu
  sudo apt install libnet1-dev
  ```

- `libpcap`

  ```bash
  # for Ubuntu
  sudo apt install libpcap-dev
  ```
