lib := libfs.a
objs := disk.o fs.o

CC := gcc
CFLAGS := -Wall -Werror -Wextra -MMD

all: $(lib)

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

$(lib): $(objs)
	ar rcs $(lib) $(objs)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(lib) $(objs) $(deps)
