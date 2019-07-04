SRC = lsha1.c lua-crypt.c

mingw: crypt.dll

linux: crypt.so

crypt.dll: $(SRC)
	gcc -o $@ -Wall --shared $^ -llua

crypt.so: $(SRC)
	gcc -o $@ -Wall -fPIC --shared $^ -llua
