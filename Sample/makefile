
APP=exec


BPFTOOL=/usr/sbin//bpftool


LINUX_KERNEL_DIR=/code/bpf-next


.PHONY: $(APP) vmlinux bpf skel run clean gdb

$(APP): skel
	clang exec.c -lbpf -lelf -lz -o $(APP)

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf: vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c exec.bpf.c -o exec.bpf.o

skel: bpf
	$(BPFTOOL) gen skeleton exec.bpf.o name ringbuf > ringbuf.skel.h

run: $(APP)
	sudo ./$(APP)

clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)


