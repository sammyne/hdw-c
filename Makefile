
CC 	?= gcc
AR 	= ar qc

ROOTDIR = $(PWD)

mbedtlsDir 	= $(ROOTDIR)/vendor/mbedtls
outDir			= $(ROOTDIR)/_build
lib 				= $(outDir)/libhdw.a
srcDir 			= $(ROOTDIR)/src

CFLAGS += -std=c11 -I$(mbedtlsDir)/include	-I$(ROOTDIR)/include
# 移植到 optee 里面时，把 $(mbedtlsDir)/library/libmbedcrypto.a 替换成响应的 libmbedtls.a
LDFLAGS += $(lib)	$(mbedtlsDir)/library/libmbedcrypto.a

SRCS=$(wildcard $(srcDir)/*.c)
OBJS=$(SRCS:.c=.o)

.PHONY: all clean

all: $(lib)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

mbedtls:
	@if [ ! -d $(mbedtlsDir) ]; then 															\
		mkdir vendor && cd vendor;																	\
		git clone -b v2.25.0 https://gitee.com/mirrors/mbedtls.git; \
		cd mbedtls;																									\
		make -j no_test;																										\
	fi

$(lib): $(OBJS) mbedtls
	rm -rf $(outDir) && mkdir $(outDir)
	$(AR) -o $@ $(OBJS)
	cp -r include $(outDir)/ && rm -rf $(outDir)/include/hdw/internal
	@echo "-----------------------------------------------------"
	@echo " artifacts have been moved into folder '$(outDir)' "
	@echo "-----------------------------------------------------"

ckd: $(lib) mbedtls
	cd examples/ckd 															&&\
	$(CC) $(CFLAGS) -c -o $@.o main.c 						&&\
	$(CC) $@.o -o $(outDir)/$@ $(LDFLAGS) $(lib) 	&&\
	$(outDir)/$@

clean:
	rm -rf $(OBJS) $(outDir)
