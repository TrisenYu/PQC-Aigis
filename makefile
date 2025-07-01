# kdf_conf ∈ {1, 2, 3}
alg_conf=1
# kdf_conf ∈ {0, 1}
kdf_conf=1
CONF=-DAIGIS_PARAM_CONF=$(alg_conf)
CONF+=-DAIGIS_KDF_CONF=$(kdf_conf)

# TODO: clang 检查

# 链接选项配置
# 
phony=build
build:
	clang enc.c $(CONF) -o e.exe
	clang sig.c $(CONF) -o s.exe

phony+=test
test:
	@echo ------------------ Test 1 ------------------
	./e.exe
	@echo ------------------ Test 2 ------------------
	./s.exe
phony+=clean
clean:
	del e.exe s.exe

.PHONY: $(phony)