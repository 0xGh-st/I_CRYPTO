#YBKim's OTP Project
<br/>
<hr/>
> * OTP 기기를 생성하기 위해 
> > * 1. OTP 기기라고 여길 새로운 디렉토리를 만든다. ex) mkdir OTPMachine1
> > > * 2. OTPChip 디렉토리에서 make 명령어를 수행
> > > * 3. createOTPMachine 디렉토리에서 make 명령어를 수행
> > > > * 4. createOTPMachine 디렉토리에서 make test 명령어를 수행
> > > > > * 5. 이 때 프로그램은 otp 기계 디렉토리 이름을 입력 받는다.(1번에서 만든 디렉토리 이름 입력)
> > > > > > * 6. 5번을 수행 후 1번에서 만든 디렉토리에 들어가면 otpChip, serialNumberCard.txt, otpHD.txt가 생성되어있다.
> > > > > > > * 7. 해당 디렉토리에서 ./otpChip 명령어를 수행하면 otp가 생성되는 것을 확인할 수 있다.(q를 입력하면 종료, 그 외 문자 입력시 다시 출력)
<hr/>
> * 생성된 OTP를 검증하는 방법
> > * 1. OTP 기기를 정상적으로 생성했을 경우 Bank 디렉토리에 있는 ServerDB에 해당 기기에 대한 정보가 쓰여져 있다.
> > > * 2. Bank 디렉토리에서 make 명령어 수행
> > > > * 3. Bank 디렉토리에서 make test 명령어 수행
> > > > > * 4. 이 때 프로그램은 먼저 시리얼 번호를 입력받는다. 생성했던 OTP 기기 디렉토리에 가면 serialNumberCard.txt를 통해 시리얼 번호를 확인할 수 있다.
> > > > > > * 5. 시리얼 번호가 일치하면 OTP를 입력받는다.
<hr/>
> * 설정에 관하여
> > * 1. 기본적으로 OTP 기기를 생성할 때 필요한 정보는 Settings 디렉토리에 settings.txt 파일에서 확인 및 변경할 수 있다.
> > > * 2. 편의를 위해 샘플로 setOTPSetting.c 파일을 제공한다. 단 이는 단순한  샘플이며, 이 프로젝트는 settings.txt에서 유효하지 않은 값에 대해서는 검증하지 않는다.
> > > > * 3. 이 settings.txt 파일에 저장된 정보를 토대로 createOTPMachine을 실행한다.
> > > > * 4. Bank 디렉토리에 있는 ServerDB.txt는 맨 윗줄에 테이블 칼럼 구성에 대해, 그리고 기본 유효시간이 30초로 설정되어 있고 OTP 기기를 생성할 때마다 자동으로 해당 기기에 대한 정보가 쓰여진다.
> > > > > * 5. 이 때, 검증 유효시간을 변경하는 것은, ServerDB.txt에서 validTime 항목에 숫자를 변경하는 것으로 가능하다.
> > > > > > * 6. 시간이 경과하여 기존에 만들었던 OTP기기의 시간이 서버시간과 맞지 않다면, ServerDB.txt에서 해당 기기의 시리얼 번호가 있는 행의 마지막 요소인 offset 값을 수정하여 보정할 수 있다.
<hr/>
###Thank You For Reading Me!!!
