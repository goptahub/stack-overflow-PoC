from sys import exit


data = ""
with open("q", "rb") as f:
    data = f.read()

unused_bytes = set()
for i in range(256):
    unused_bytes.add(i)

for byte in data:
    unused_bytes.discard(byte)

if not unused_bytes:
    print("[-] all bytes are in use")
    exit(1)

xor_byte = unused_bytes.pop()
print(f"[+] xor_byte: {xor_byte}")

xored_data = bytes([b ^ xor_byte for b in data])

with open("xored_q", "wb") as f:
    f.write(xored_data)

