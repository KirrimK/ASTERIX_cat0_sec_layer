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

Each gateway has a json configuration file, which follows the following format:

(//this is a comment in the following examples, and should not be in the final files)
### Receiver Gateway

```json

{
    "iek_path": "config/iek1", // path of the file containing the IEK of the user group this receiver belongs to
    "ca_ip": "127.0.0.1", // associated port
    "ca_port": 42000,   // port of the CA (deprecated, will be removed if no CA is used)
    "multicast_ip": "224.1.1.2", // IP address of the multicast group this receiver belongs to
    "multicast_port": 10000, // associated port
    "bound_ip": "127.0.0.1", // IP address of the interface this receiver is bound to (to receive keys)
    "bound_port": 42080, // associated port
    "self_ext_ip": "192.168.0.1", // the agent's own IP address (a trick to fix an issue if sender is on the same machine)
    "legacy_output_mcast_ip": "224.1.1.4", // IP address where insecure messages will be relayed
    "legacy_output_mcast_port": 9998, // associated port
    "mode": "gateway", // mode of the agent (gateway or interactive): gateway means that the agent will act as a gateway, interactive means that the agent will display received messages to the standard output. No legacy receiver is needed if the mode is interactive.
    "actions": { // actions that the agent will perform: relay means that the message will be relayed to the legacy receiver, drop means that the message will be dropped
        "sign_ok": "relay", // action to take when the signature is valid
        "sign_no": "drop", // action to take when the signature is invalid
        "no_sec": "drop" // action to take when the message is not secured
    }
}

```

### Sender Gateway

```json

{
    "legacy_input_mcast_ip": "224.1.1.1", // IP address of the multicast group this sender will receive messages to secure from (where the legacy sender is expected to send messages)
    "legacy_input_mcast_port": 9999, // associated port
    "mode": "gateway", // mode of the agent (gateway or interactive): gateway means that the agent will act as a gateway, interactive means that the agent will send messages from the standard input. No legacy sender is needed if the mode is interactive.
    "user_groups": [ // list of user groups this sender will relay messages to
        {
            "iek_path": "config/iek1", // path of the file containing the IEK of the user group
            "ca_ip": "127.0.0.1", // IP address of the group's CA (deprecated, will be removed if no CA is used)
            "ca_port": 42000, // associated port

            "expected_receivers": [ // list of receivers to contact
                {"ip": "127.0.0.1", "port": 42080},
                {"ip": "192.168.0.2", "port": 42080}
            ],
            "asterix_multicast_ip": "224.1.1.2", // IP address of the multicast group this sender will send secure messages to
            "asterix_multicast_port": 10000 // associated port
        },
        ...
    ]
}

```

## Usage

Configure the agents using the config files above, then launch the agents: ```python src/[receiver sender].py <config_file_path>```. (Launch the receivers first, then the senders)
You can also launch legacy agents: ```python src/basic_[recv sender].py```. These have no config files, but will require you to input the IP addresses of the multicast groups and ports manually.

## Notes

(cf https://github.com/fernet/spec/blob/master/Spec.md for Fernet cipher spec)

## Project TODOs

- how to share infos between user-groups? Put several IEKs on device? how? study practicality
- add rule to drop or relay messages of improper size
