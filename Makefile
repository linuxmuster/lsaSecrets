CC=cl.exe
CCFLAGS=/nologo /EHsc /W4 /c

LNK=link.exe
LDFLAGS=/nologo

INC_DIR=inc 
SRC_DIR=src
OUTPUT_DIR=bin

SQLITE_DIR=3rd_party\sqlite
	
# Inference rule to build all object files
{$(SRC_DIR)}.cpp.obj ::
	@echo -------Compiling $<
	$(CC) $(CCFLAGS) /I$(INC_DIR) $<

all : protect encrypt decrypt lsaSecretRead lsaSecretStore chromePass iePass firePass

utils.obj : $(INC_DIR)\utils.h
firePass.obj : $(INC_DIR)\firePass.h

# Build executables with nmake macros
protect encrypt decrypt: $@.obj
	$(LNK) $(LDFLAGS) /out:$(OUTPUT_DIR)\$@.exe  $*.obj 

lsaSecretRead lsaSecretStore: $@.obj lsa_util.obj
	$(LNK) $(LDFLAGS) /out:$(OUTPUT_DIR)\$@.exe  $*.obj lsa_util.obj  

chromePass firePass: $@.obj utils.obj
	$(LNK) $(LDFLAGS) /out:$(OUTPUT_DIR)\$@.exe  $*.obj utils.obj $(SQLITE_DIR)\sqlite3.obj

iePass: $@.obj utils.obj
	$(LNK) $(LDFLAGS) /out:$(OUTPUT_DIR)\$@.exe  $*.obj utils.obj
	
clean:
	del *.obj *.tli *.tlh
	 
cleanall:
	del $(OUTPUT_DIR)\*.exe *.obj *.tli *.tlh