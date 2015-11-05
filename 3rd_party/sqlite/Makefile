CC=cl
CCFLAGS=/EHsc

#nmake macros:
#	$@	- Current target's full name
 
all:sqlite3 shell

sqlite3:$@.c
	@echo --- Build sqlite3 object
	$(CC) $(CCFLAGS) /c $@.c

shell:sqlite3 $@.c
	@echo --- Build sqlite3 shell
	$(CC) $(CCFLAGS) $@.c sqlite3.obj
	
clean:
	del *.obj
	 
cleanall:
	del *.exe *.obj