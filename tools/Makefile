

TOOLS= img_raw

CFLAGS = 
LDFLAGS = 

CC = cc

all: $(TOOLS)

define genobj
$1: $1.c
	$(CC) $(CFLAGS) $$< -o $$@
endef

$(foreach m, $(TOOLS), $(eval $(call genobj, $(m))))

.PHONY: clean

clean:
	-rm -rf $(TOOLS) *.o
