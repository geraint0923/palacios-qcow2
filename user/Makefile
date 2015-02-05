

DEPS := v3_qcow2.h

all: qcow2_user

qcow2_user: qcow2_user.o v3_qcow2.o

qcow2_user.o: qcow2_user.c $(DEPS)

v3_qcow2.o: v3_qcow2.c $(DEPS)

.PHONY: clean

clean:
	-rm -rf *.o qcow2_user
