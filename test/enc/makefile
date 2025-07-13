kdf_conf=0
alg_conf=1

AIGIS_CONF=-DAIGIS_PARAM_CONF=$(alg_conf)
AIGIS_CONF+=-DAIGIS_KDF_CONF=$(kdf_conf)

flags=-O3
# -ftrapv

clang_test=$(shell clang --version)
ifneq ($(clang_test),)
	CC:=clang
else
	CC:=gcc
endif

# windows 真是问题多多
ifeq ($(OS),Windows_NT)
	RM=del
	CC=gcc
	suffix=.exe
else
	RM=rm
	suffix=.out
endif

test-src=$(wildcard *.c)
test-exe=$(patsubst %.c,%$(suffix), $(test-src))

phony=build
build: $(test-exe)

%$(suffix): %.c
	$(CC) $(AIGIS_CONF) $(flags) -o $@ $<


# 非预期var？那windows怎么办？
phony+=run
run:
	@for var in $(test-exe); do \
		echo [$$var];			\
		./$$var;	  			\
	done

phony+=clean
clean:
	$(RM) *$(suffix)

.PHONY: $(phony)
