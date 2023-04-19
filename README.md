<h1 align="center">Clover P2P Reverse Shell</h1>
<p align="center">
    <img alt="Clover P2P Reverse Shell" src="clover.png">
</p>
Clover P2P Reverse Shell allows you to establish a a decentralized peer-to-peer (P2P) connection between two computers and execute shell commands on the remote computer.


<br>

## Features 

- Secure communication using AES encryption <br>
- Ability to execute shell commands on the remote computer <br>
- Option to choose between listening for incoming connections or connecting to a peer <br>
- Automatic key generation or manual key specification for added security <br>
- Decentralized peer-to-peer communication <br>
- Cross-platform compatibility. <br>
- Add a command in queue with "-q" flag

## Requirements

To use Clover P2P Reverse Shell, you must have Python 3 installed on both computers.
<br>

## Installation
<br>
Clone or download the repository to your local machine.
Install the required packages by running pip install -r requirements.txt in your terminal or command prompt.
<br>

## Prerequisites

- Python 3.x <br>
- PyCryptodome

## Usage

<br>
Start the script on both computers by running python clover.py in your terminal or command prompt.
Choose the mode you want to use: either listen for incoming connections or connect to a peer.
Follow the on-screen instructions to enter the necessary information, such as the local port to listen on, the peer host to connect to, and the encryption key.
Once connected, you can execute shell commands on the remote computer by entering them in the command prompt.


## Example

<img alt="Clover P2P Reverse Shell" src="2.png">

<br>

<img alt="Clover P2P Reverse Shell" src="1.png">


## Security 

Clover P2P Reverse Shell uses AES encryption for secure communication between the peers. By default, a new key is generated automatically when the script is started in listen mode. Alternatively, you can specify a key manually when starting the script.

It is recommended that you use a strong, random key and keep it confidential. You should also be careful not to leak the key over an insecure channel. <br> 
## Disclaimer:

This project is intended for educational purposes only. The goal of this project is to learn how to establish a peer-to-peer (P2P) connection between two computers and execute shell commands on the remote computer. The project is not intended to be used for malicious purposes or to cause harm to any individual or organization. The authors of this project do not condone any illegal or unethical use of this software.
