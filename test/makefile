kdf_conf=0
alg_conf=1

AIGIS_CONF=-DAIGIS_PARAM_CONF=$(alg_conf)
AIGIS_CONF+=-DAIGIS_KDF_CONF=$(kdf_conf)

flags=-O3 -g

clang_test=$(shell clang --version)
ifneq ($(clang_test),)
	CC:=clang
else
	CC:=gcc
endif

ifeq ($(OS),WindowsNT)
	RM=del
else
	RM=rm
endif

test-src=$(wildcard  *.c)
test-exe=$(patsubst %.c,%.exe, $(test-src))
build: $(test-exe)

%.exe: %.c
	$(CC) $(AIGIS_CONF) $(flags) -o $@ $<

# gcc test_ntt.c $(CONF) $(comp_conf) -o a.exe
# gcc test_rej.c $(CONF) $(comp_conf) -o b.exe
# gcc test_comp.c $(CONF) $(comp_conf) -o c.exe
# gcc test_enc.c $(CONF) $(comp_conf) -o e.exe
# gcc test_mat.c $(CONF) $(comp_conf) -o m.exe

run:
	@for var in $(test-exe); do \
		echo [$$var];			\
		./$$var;	  			\
	done

clean:
	$(RM) *.exe
