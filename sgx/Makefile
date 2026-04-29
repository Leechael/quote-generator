SGX_SDK ?= /usr/lib/sgx-sdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x64)
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
endif

SGX_COMMON_FLAGS += -O2 -Wall -Wextra
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

######## App Settings ########

ifneq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -DNDEBUG
endif

App_C_Files := App.c
App_Include_Paths := -I. -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts -lsgx_dcap_ql -lpthread -ldl

ifneq ($(SGX_DEBUG), 1)
	App_Link_Flags += -L$(SGX_LIBRARY_PATH) -lsgx_pthread
endif

App_C_Objects := $(App_C_Files:.c=.o)

App_Name := quote-generator

######## Enclave Settings ########

Enclave_C_Files := Enclave.c
Enclave_Include_Paths := -I. -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong $(Enclave_Include_Paths)
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-as-needed \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave.config.xml

ifeq ($(SGX_MODE), HW)
	ifeq ($(SGX_DEBUG), 1)
		Build_Mode = HW_DEBUG
	else
		Build_Mode = HW_RELEASE
	endif
else
	ifeq ($(SGX_DEBUG), 1)
		Build_Mode = SIM_DEBUG
	else
		Build_Mode = SIM_RELEASE
	endif
endif

.PHONY: all target clean

all: $(App_Name)

target: $(App_Name)

clean:
	rm -f $(App_Name) $(App_C_Objects) \
		$(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_C_Objects) \
		Enclave_t.c Enclave_t.h Enclave_u.c Enclave_u.h *.pem

######## App Objects ########

Enclave_u.c: $(SGX_EDGER8R) Enclave.edl
	$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include --search-path $(SGX_SDK)/include/edl
	@echo "GEN  >  $@"

Enclave_u.h: Enclave_u.c

Enclave_u.o: Enclave_u.c Enclave_u.h
	@echo "CC   <=  $<"
	@$(CC) $(App_C_Flags) -c $< -o $@

App.o: App.c Enclave_u.h
	@echo "CC   <=  $<"
	@$(CC) $(App_C_Flags) -c $< -o $@

######## Enclave Objects ########

Enclave_t.c: $(SGX_EDGER8R) Enclave.edl
	$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include --search-path $(SGX_SDK)/include/edl
	@echo "GEN  >  $@"

Enclave_t.h: Enclave_t.c

Enclave_t.o: Enclave_t.c Enclave_t.h
	@echo "CC   <=  $<"
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave.o: Enclave.c Enclave_t.h
	@echo "CC   <=  $<"
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

$(Enclave_Name): Enclave_t.o $(Enclave_C_Objects)
	@echo "LINK >=  $@"
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	@echo "SIGN >=  $@"
	@openssl genrsa -out private.pem -3 3072 2>/dev/null
	@$(SGX_ENCLAVE_SIGNER) sign -key private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@rm -f private.pem

$(App_Name): Enclave_u.o $(App_C_Objects) $(Signed_Enclave_Name)
	@echo "LINK >=  $@"
	@$(CC) Enclave_u.o $(App_C_Objects) -o $@ $(App_Link_Flags)
