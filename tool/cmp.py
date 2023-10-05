#! /usr/bin/python


import sys, mmap


f1 = open(sys.argv[1], "rb")
f2 = open(sys.argv[2], "rb")

m1 = mmap.mmap(f1.fileno(), 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
m2 = mmap.mmap(f2.fileno(), 0, mmap.MAP_PRIVATE, mmap.PROT_READ)

i=0
while i<len(m1) and i<len(m2) and m1[i]==m2[i]:
    i+=1

print("files differ @", i)

mism=[]
j=0
while i<len(m1) and i<len(m2):
    if m1[i]!=m2[i]:
        j+=1
        a=i
        i+=1
        while i<len(m1) and i<len(m2):
            if m1[i]!=m2[i]:
                i+=1
                j+=1
            else:
                break
        mism.append((a,i-1))
    i+=1

mism.sort()
for a,b in mism:
    print(a, b, sep='-', end=', ')
print()

print(j,"bytes differ")

if len(m1)!=len(m2):
    print("file size",len(m1),"vs.",len(m2))

m1.close()
m2.close()
f1.close()
f2.close()

