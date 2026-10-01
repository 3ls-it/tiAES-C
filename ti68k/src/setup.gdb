set print pretty
set pagination off
set args e core.h out.enc
break main
break bzero
break readpassphrase
break ke
break cbcenc
break enc
run
