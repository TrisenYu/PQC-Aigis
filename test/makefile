kdf_conf=1
# 好像第三个参数炸了
alg_conf=3
CONF=-DAIGIS_PARAM_CONF=$(alg_conf)
CONF+=-DAIGIS_KDF_CONF=$(kdf_conf)

build:
	gcc test_ntt.c $(CONF) -O3 -o a.exe
	gcc test_rej.c $(CONF) -O3 -o b.exe
	gcc test_comp.c $(CONF) -O3 -o c.exe
	gcc test_enc.c $(CONF) -O3 -o e.exe

run:
	@echo -------------------- Test 1 --------------------
	@./a.exe
	@echo -------------------- Test 2 --------------------
	@./b.exe
	@echo -------------------- Test 3 --------------------
	@./c.exe
	@echo -------------------- Test 3 --------------------
	@./e.exe

clean:
	del *.exe