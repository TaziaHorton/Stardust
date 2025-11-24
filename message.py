from typing import List
import sys

RECV_SIZE = 100  # Full packet size w/ TCP IP headers

HEADER = b"\x13STARDUST\x17\n"
HEADER_SIZE = len(HEADER) + 1 + 2 + 2 + 2 + 1 + 1
PAYLOAD_SIZE = RECV_SIZE - HEADER_SIZE
PAYLOAD_SIZE_BITS = PAYLOAD_SIZE * 8


class Message:
    SYN = "SYN"
    ACK = "ACK"
    NAK = "NAK"
    GET = "GET"
    SET = "SET"
    DAT = "DAT"
    FIN = "FIN"
    ENC = "ENC"
    allFlags = [SYN, ACK, NAK, GET, SET, DAT, FIN, ENC]

    def __init__(
        self,
        connNo: int,
        *,
        seqNo: int,
        ackNo: int,
        _flag: List[str],
        version: int = 2,
        message: str = "",
    ) -> None:
        self.connNo: int = connNo
        self.seqNo: int = seqNo
        self.ackNo: int = ackNo
        if _flag is None or len(_flag) == 0:
            raise ValueError("At least one flag must be set")
        self._flag: List[str] = _flag
        self.set_flag()
        self.version: int = version
        self.message: str = message

    def __repr__(self) -> str:
        msg = f',\n\tmsg: "{self.message}"'
        rep = f"< Message: conn: {self.connNo}, seq: {self.seqNo}, ack: {self.ackNo}, flags: {self._flag}, v: {self.version} {msg}>"
        return rep

    def read_flags(byte: int) -> List[str]:
        pattern = bin(byte)[2:].zfill(8)
        return [Message.allFlags[index] for index, content in enumerate(pattern) if content == "1"]

    def set_flag(self) -> None:
        self.flag: int = 0b00000000
        for flag in self._flag:
            self.flag |= 1 << (7 - Message.allFlags.index(flag))

    def is_flags(self, *flags: str) -> bool:
        if any(flag not in Message.allFlags for flag in flags):
            raise ValueError("Invalid flag provided")
        return set(self._flag) == set(flags)

    def has_flag(self, flag: str) -> bool:
        if flag not in Message.allFlags:
            raise ValueError("Invalid flag provided")
        return flag in self._flag

    def build_header(self) -> bytes:
        def add_short(arr: bytearray, num: int) -> None:
            arr.append(num >> 8)
            arr.append(num & 0x00FF)

        prefix = HEADER

        result = bytearray()
        result += prefix
        result.append(self.version)
        add_short(result, self.connNo)
        add_short(result, self.seqNo)
        add_short(result, self.ackNo)
        result.append(self.flag)
        result += b"\n"
        return result

    def build_packet(self) -> bytes:
        result = b""
        result += self.message.encode("UTF-8")
        if len(result) > PAYLOAD_SIZE:
            raise ValueError("Message too long to fit in payload")
        result += b"\x00" * (PAYLOAD_SIZE - len(result))
        if Message.ENC in self._flag:
            result = self.encode(result)
        result = self.build_header() + result
        return result

    def encode(self, payload: bytes) -> bytes:
        key = self.connNo & 0xFF
        result = bytearray()
        for c in payload:
            result.append(c ^ key)
        return result

    @staticmethod
    def read_data(data: str):
        try:
            raw = bytes.fromhex(data)
            # read data from bytes
            s = len(HEADER)
            header = raw[:s]
            if header != HEADER:
                return None
            version = int.from_bytes(raw[s : s + 1], byteorder="big")
            s += 1  # Single byte
            connNo = int.from_bytes(raw[s : s + 2], byteorder="big")
            s += 2  # Two bytes
            seqNo = int.from_bytes(raw[s : s + 2], byteorder="big")
            s += 2  # Two bytes
            ackNo = int.from_bytes(raw[s : s + 2], byteorder="big")
            s += 2  # Two bytes
            flags = Message.read_flags(int.from_bytes(raw[s : s + 1], byteorder="big"))
            s += 1  # Single byte
            s += 1  # Single byte (Newline)
            message = raw[s:]
            try:
                message = message.rstrip(b"\x00")
            except:
                message = "BAD ENCODING"
            if len(raw) > RECV_SIZE:
                message = "BAD ENCODING"
            return Message(connNo, seqNo=seqNo, ackNo=ackNo, _flag=flags, version=version, message=message)
        except Exception as e:
            return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python message.py <mode>")
        print("Modes: read - Read message from hex input")
        print("       build - Build message from parameters")
        return
    try:
        mode = sys.argv[1]
        if mode == "read":
            data = input("Enter hex data: ").strip()
            msg = Message.read_data(data)
            if msg is None:
                print("Failed to read message.")
            else:
                print(msg)
            return
        connNo = int(input("Enter connection number: "))
        seqNo = int(input("Enter sequence number: "))
        ackNo = int(input("Enter acknowledgment number: "))

        flags_input = input("Enter flags (comma-separated): ").strip()
        flags = [flag.strip().upper() for flag in flags_input.split(",")]

        version_input = input("Enter version (default 2): ").strip()
        version = int(version_input) if version_input else 2

        message = input("Enter message: ")

        msg = Message(connNo, seqNo=seqNo, ackNo=ackNo, _flag=flags, version=version, message=message)
        packet = msg.build_packet()
        print(packet.hex())

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
