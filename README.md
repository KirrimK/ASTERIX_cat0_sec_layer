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

To keep being compatible with legacy systems, the proof of concept is designed around the idea of having gateways, which means that there are 4 types of agents:
- legacy senders: sources of information on the network, send unsecure ASTERIX messages
- legacy receivers: consumers of information on the network, receives unsecure ASTERIX messages
- sender gateways: transform unsecure ASTERIX messages from their attached legacy sender into "secured" messages that are sent over the network
- receiver gateways: receives "secured" messages from the network, processes them and relays them their attached legacy receiver

(TODO: continue explanations)

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
