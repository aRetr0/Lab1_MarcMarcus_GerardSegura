# Lab1_MarcMarcus_GerardSegura

This project is a Python-based implementation of a traceroute-like tool using ICMP packets. It includes multiple
versions of the tool, each adding more features and improvements.

## Project Structure

- `mtr1.py`: Basic implementation of sending ICMP packets to trace the route to a target.
- `mtr2.py`: Adds round-trip time (RTT) calculation and hostname resolution.
- `mtr3.py`: Adds RTT statistics (min, max, avg, stdev) for each hop.
- `mtr4.py`: Adds a curses-based UI to display the traceroute results in real-time.

## Requirements

- Python 3.x
- Root or sudo privileges to run the scripts
- `curses` library (for `mtr4.py`)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/aRetr0/Lab1_MarcMarcus_GerardSegura.git
    cd Lab1_MarcMarcus_GerardSegura
    ```

2. Ensure you have the necessary permissions to run the scripts:
    ```sh
    sudo chmod +x mtr1.py mtr2.py mtr3.py mtr4.py
    ```

## Usage

Run any of the scripts with root privileges and provide a target domain as an argument:

```sh
sudo python mtr1.py <target_domain>
sudo python mtr2.py <target_domain>
sudo python mtr3.py <target_domain>
sudo python mtr4.py <target_domain>
```

For example:

```sh
sudo python mtr1.py example.com
```

## Features

### mtr1.py

- Sends ICMP packets to trace the route to a target.
- Displays each hop's IP address.

### mtr2.py

- Adds RTT calculation for each hop.
- Resolves IP addresses to hostnames.

### mtr3.py

- Adds RTT statistics (min, max, avg, stdev) for each hop.
- Displays detailed RTT statistics for each hop.

### mtr4.py

- Adds a curses-based UI to display the traceroute results in real-time.
- Displays packet loss percentage for each hop.

## Authors

The authors of this project are:

- Marc Marcus
- Gerard Segura