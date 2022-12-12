all : get_offsets_in_structs

get_offsets_in_structs : get_offsets_in_structs.c
	$(CC) -o $@ -Wall -Wextra -ggdb -O3 $^

.PHONY : clean
clean :
	rm -f *~ get_offsets_in_structs
