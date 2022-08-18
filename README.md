# ASTERIX Category 0 Security Layer - Proof of Concept

(TODO: Add a short description of the project here)

## Goal of the project

(Note: the specifics of the ASTERIX protocol were not the main point of study of this project)

Currently, messages sent between agents using the ASTERIX protocol are sent over UDP multicast in plaintext,
the reason for that being ease of distribution of the messages from one sender to multiple receivers, and safety of operations. Moreover, there is no point in encrypting the content of those messages, since it is not confidential.

However, this means that a malicious actor, should they gain access to the "ASTERIX network", could start emitting unsolicited messages to receivers, and disrupt the operations of those receivers (and everything relying on those receivers).
The malicious actor could also impersonate an existing source of information on the network and alter the information that is sent over the network.

As such, the goal of this project was to design a security layer (and implement a working proof of concept) for the existing protocol that could prevent those situations from happening, while satisfying the existing performance specifications of ASTERIX.

## How it works

To keep being compatible with legacy components, the proof of concept is designed around the idea of having gateways, which means that there are 4 types of agents:
- legacy senders: sources of information on the network, send unsecure ASTERIX messages
- legacy receivers: consumers of information on the network, receive unsecure ASTERIX messages
- sender gateways: transform unsecure ASTERIX messages from their attached legacy sender into "secured" messages that are sent over the network
- receiver gateways: receives "secured" messages from the network, processes them and relays them their attached legacy receiver

All those agents are split into user groups, which share the same UDP multicast address (which is how ASTERIX messages are sent over the network):
- a receiver only belongs to one user group
- a sender car be shared among multiple user groups

The securisation protocol works as follows:

### Initialisation Phase

During the factory initialisation, gateways are fitted with Initiation Encryption Keys (IEKs), AES encryption keys used only for keysharing:
- for a receiver gateway, the IEK of the user group it belongs to
- for a sender gateway, the IEKs of each user group it will send information to
These keys have a lifetime of 5-10 years, and so, should be sufficiently long to prevent attacks (our PoC uses 256-bit long keys).

Each gateway generates its own Ed25519 keypair, which be used for later steps.

### Keysharing Phase

Each sender gateway will contact each receiver gateway it is supposed to contact over TCP, and send its own public key (encrypted with the IEK of the user group it belongs to).
In response, the receiver gateway will send its own public key (encrypted with the IEK of the user group it belongs to).

Each keypair is supposed to have a lifetime of 6-12 months.

### HMAC Key diffusion Phase

Each sender gateway generates a 20-bytes long HMAC key per user group it belongs to.
This key is then sent to each receiver in the group after being signed using the sender's Ed private key, and encrypted with each receiver's Ed public key.

Each receiver, upon receiving that key, will decrypt it using its Ed private key, and verify that the signature is valid to ensure that the HMAC key is not forged.

Each HMAC key is supposed to have a lifetime of a day at most.

### Nominal Phase

Each time a legacy sender sends an ASTERIX message, it will be received the sender gateway, and for each user group, the message will be signed with the HMAC key of the sender for that group, then sent over UDP multicast to all receivers in the group.

Each receiver gateway, upon receiving a message, will fetch the HMAC key of the sender gateway and try to verify the signature. The message can then be relayed to a legacy receiver or dropped.

## Installation

Create a python virtual environment (using ```virtualenv venv```),
then, inside that virtual environment, install the requirements (```pip install -r requirements.txt```).

## Configuration


## Usage


## Notes

(cf https://github.com/fernet/spec/blob/master/Spec.md for Fernet cipher spec)

## Project TODOs

- how to share infos between user-groups? Put several IEKs on device? how? study practicality
- add rule to drop or relay messages of improper size
- document code and config files
