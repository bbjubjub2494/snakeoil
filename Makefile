objs = \
      circle.o \
      decryption.o \
      encryption.o \
      except.o \
      helper.o \
      map.o \
      mem.o \
      pads.o \
      pps.o \
      psp.o \
      prime.o \
      spaestr.o \
      spechars.o \
      userkey.o \
      main.o 

libspae.so: $(objs)
