CC=/usr/bin/gcc
CFLAGS += -O3 -march=native -fomit-frame-pointer
LDFLAGS=-lcrypto

SOURCES1= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c PQCgenKAT_kem.c reduce.c rng.c verify.c symmetric-shake.c
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h

SOURCES2= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c client.c reduce.c rng.c verify.c symmetric-shake.c
SOURCES3= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c server.c reduce.c rng.c verify.c symmetric-shake.c
SOURCES4= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c recovery.c reduce.c rng.c verify.c symmetric-shake.c

PQCgenKAT_kem: $(HEADERS) $(SOURCES1)
	$(CC) $(CFLAGS) -o $@ $(SOURCES1) $(LDFLAGS)

server: $(HEADERS) $(SOURCES3)
	$(CC) $(CFLAGS) -o $@ $(SOURCES3) $(LDFLAGS)

client: $(HEADERS) $(SOURCES2)
	$(CC) $(CFLAGS) -o $@ $(SOURCES2) $(LDFLAGS)

recovery: $(HEADERS) $(SOURCES4)
	$(CC) $(CFLAGS) -o $@ $(SOURCES4) $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem server client recovery

