f = open("data.bin", 'rb')
f.read(4)
data = f.read()
data_size = len(data)
length = data_size << 1
out_buf = [0 for _ in range(length)]
print(data_size, length)
i, block, base, tmp = 0, 0, 0, 0
while i != data_size:
    print("idxs", i, tmp, base, block)
    if block == 0:
        base = int.from_bytes(data[i:i+2][::-1])
        i += 2
        block = 0x10
    if (base & 1) == 0:
        out_buf[tmp] = data[i]
        tmp += 1
        i += 1
    else:
        c = data[i]
        next = data[i + 1]
        i += 2
        x1 = tmp - (next + (c & 0xf0) * 0x10)
        x2 = (c & 0xf) + 1
        while x2 != 0:
            print("tmps", tmp, x1, x2)
            out_buf[tmp] = out_buf[x1]
            tmp += 1
            x1 += 1
            x2 -= 1
    base = base >> 1
    block -= 1
length = tmp
print(hex(length))
out_buf = bytes(out_buf[:length])

with open("output_file.bin", 'wb') as f:
    f.write(out_buf)





