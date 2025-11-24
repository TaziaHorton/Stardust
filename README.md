# Stardust

Stardust is a new proprietary Automated ore collection system built for the Space Fe-Ore Corporation.

It builds on similar PLC systems used in previous mining operations, but has been optimized for the unique challenges of mining in space.

The message protocol follows a similar initial connection protocol to TCP (SYN, SYN-ACK, ACK), but diverges significantly in the data transfer phase.

The protocol includes a header packet that includes: a prefix identifying the protocol as Stardust, a version number (byte), a connection number (short), a sequence number (short), an acknowledgement number (short) and a flag byte indicating the type of message.

There are 8 different Flags that can be set in each message.

- SYN
- ACK
- NAK
- GET
- SET
- DAT
- FIN
- ENC

To start a connection the initial SYN message will always have a sequence and connection number of 0.
The server will respond with the starting sequence number and connection number for the following messages.

The Following permutations of Flags are valid in messages:

- SYN: Initial connection request
- SYN + ACK: Acknowledgement of connection request, includes assigned connection, sequence numbers, encryption key to be used for message contents if ENC flag is set
- ACK: Acknowledgement of received message - ensure that all ACK messages have the acknowledgement number set to the sequence number of the message being acknowledged. Otherwise ACK number is 0.
- NAK: No Acknowledgement, requests server to resend last message
- FIN: Termination of connection
- GET: Request to read a specific Readable register (Denoted QX0, SX0, Flag, etc.)
- GET + FIN: Bad GET request, tried to read not readable register
- DAT: Data message containing requested data, wait for confirmation before proceeding
- DAT + FIN: Data message containing requested data, FIN denotes no more data messages to follow
- SET: Request to write to a specific Writeable register (Denoted IX0, IX1, etc.), followed by a space and a byte to represent the new state of the register
- SET + FIN: Bad SET request, tried to write to not writeable register
- SET + DAT + FIN: Data message containing new state of register
- Any DAT message can also have the ENC flag set, indicating the message contents are encrypted with a simple XOR cipher using the key provided in initial connection setup

The sequence number will be incremented for each message sent, note that not all messages sent by a client as a part of a request will require a response from the server.

Improper messages by a client will either be ignored or result in the server terminating the connection.
A client has to be connected before it can send GET or SET requests.

## Example Communication

C: 135354415244555354170a02000000000000800a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

S: 135354415244555354170a0286fa062d0000c00a3235300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

C: 135354415244555354170a0286fa062e062d400a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

C: 135354415244555354170a0286fa062f0000100a5158300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

S: 135354415244555354170a0286fa0630062f060a0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
