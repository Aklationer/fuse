FILESYSTEM_FILES = a.c
OPENSSL_INCLUDE = -I./openssl/include
OPENSSL_LIB = -L./openssl -lssl -lcrypto

build: $(FILESYSTEM_FILES)
	gcc  $(FILESYSTEM_FILES) -o lsysfs `pkg-config fuse --cflags --libs` $(OPENSSL_INCLUDE) $(OPENSSL_LIB)

clean:
	rm ssfs