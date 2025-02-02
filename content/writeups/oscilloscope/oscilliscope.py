import numpy as np
import matplotlib.pyplot as plt

import pickle

with open("trace.pckl", "rb") as f:
     time, clock, data = np.array(pickle.load(f))

#print(len(time))
#print(len(clock))
#print(len(data))

high = 3.3
low = 0
clock = np.where(clock >= 1.0, high, low)

#plt.plot(clock)
#plt.plot(data)
#plt.show()

pos_edge = np.where((clock[:-1] == low) & (clock[1:] == high))[0]
bin = np.array([int(data[int(c)] > 2.8) for c in pos_edge])
flag = ""
for i in range(37, len(bin), 9):
    c = int(''.join(str(bit) for bit in bin[i:i+8]), 2)
    flag += chr(c)
print(flag)
