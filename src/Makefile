obj-m += ip_route_input_slow_hook.o

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

.PHONY: build
build:
	make -C /lib/modules/$(shell uname -r)/build M=$(mkfile_dir) modules

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(mkfile_dir) clean

.PHONY: sign
sign:
	kmodsign sha512 /var/lib/shim-signed/mok/MOK.priv /var/lib/shim-signed/mok/MOK.der ip_route_input_slow_hook.ko

.PHONY: unload
unload:
	rmmod ip_route_input_slow_hook

.PHONY: load
load:
	insmod ip_route_input_slow_hook

.PHONY: sign_load

sign_load: sign load
all: build sign load
