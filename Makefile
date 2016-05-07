

win32: win32_crypto win32_iguana

win64: win64_crypto win64_iguana

#build for win32 environment
win32_crypto:
	cd crypto777; make -f make_win32; cd ..

win32_iguana:
	cd iguana; make -f make_win32; cd ..

#build for win64 environment
win64_crypto:
	cd crypto777; make -f make_win64; cd ..

win64_iguana:
	cd iguana; make -f make_win64; cd ..


