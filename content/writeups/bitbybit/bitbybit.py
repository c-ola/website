def decrypt(msg, key):
    iv = 0
    chunks = [msg[i:i+32] for i in range(0,len(msg) - 32, 32)]
    dec = b''
    i = 0
    for chunk in chunks:
        iv = (iv+1) % 255
        curr_k = key+iv
        enc = int(chunk, 16) ^ curr_k
        dec += enc.to_bytes(16)
        print(i, ":", enc.to_bytes(16))
        i += 1
    return dec

def crib_check(msg, idx, key, crib):
    chunks = [msg[i:i+32] for i in range(0, len(msg) - 32, 32)]

    a = chunks[idx]
    b = chunks[(idx + 255) % len(chunks)]
    iv = (idx + 1) % 256
    curr_key = key + iv
    a_e = int(a, 16) ^ curr_key
    b_e = int(b, 16) ^ curr_key
    print(a_e.to_bytes(16))
    print(b_e.to_bytes(16))

    x = a_e ^ b_e
    crib_e = int.from_bytes(crib.encode()) << (16 * 8 - len(crib) * 8)
    output = x ^ crib_e
    print(output.to_bytes(16))
    new_key = output ^ b_e
    return (new_key, 16* 8 - len(crib) * 8)

if __name__=="__main__":
    file = open("out.txt", "r", encoding='utf-8')
    msg = file.read()
    file.close()

    key = 0
    (gained_key, crib_len) = crib_check(msg, 0, key, 'Chapter 1 ')
    key += gained_key >> crib_len << crib_len

    (gained_key, crib_len) = crib_check(msg, 294, key, 'of information ') 
    key += gained_key >> crib_len << crib_len

    (gained_key, crib_len) = crib_check(msg, 361, key, ' the friendships')
    key += gained_key >> crib_len << crib_len

    # mysterious - 1 idk
    dec = decrypt(msg, key - 1)
    print(dec.decode('utf-8'))
