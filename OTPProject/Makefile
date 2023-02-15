DST = OTPPackage
PRJ = Bank OTPChip createOTPMachine Settings otp_library
DIRS = otp_library/src Bank OTPChip createOTPMachine
.PHONY: all clean

all:
	@for d in $(DIRS); \
	do \
			$(MAKE) -C $$d; \
	done

doc:
	doxygen Doxygen/otp_conf
	mv html Doxygen/

package:
	#전체 디렉토리 복사
	@for d in $(PRJ); \
	do \
			cp -r $$d $(DST); \
	done	
	#object 파일 제거
	@for d in $(DIRS);\
	do \
			rm -f $(DST)/$$d/*.o; \
	done
	#소스코드 제거
	rm -rf $(DST)/otp_library/src
	#doc 라이브러리에 html 포함하기
	mkdir $(DST)/otp_library/doc
	cp -r Doxygen/html $(DST)/otp_library/doc
	tar -cvf OTP_Manual.tar $(DST)/otp_library/doc/html/
	rm -rf $(DST)/otp_library/doc/html/
	mv OTP_Manual.tar $(DST)/otp_library/doc/
	#압축
	tar -cvf otpPackage.tar $(DST)

clean:
	@for d in $(DIRS); \
	do \
			$(MAKE) -C $$d clean; \
	done
	rm -rf Doxygen/html/
	@for d in $(PRJ); \
	do \
			rm -rf $(DST)/$$d; \
	done
