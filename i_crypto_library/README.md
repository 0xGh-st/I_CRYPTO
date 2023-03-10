# I_CRYPTO_LIBRARY


* 이 디렉토리는 직접 구현한 crypto 라이브러리 코드가 저장되어 있습니다.
<hr>


## 각 디렉토리별 설명


* include
> 1. i_crypto.h 파일이 들어있습니다.
> > 2. 해당 파일의 주석은 Doxygen 문법에 맞게 작성하여 문서화를 가능하게 하였습니다.


* src
> 1. 작성한 코드가 들어있는 i_crypto.c 파일이 저장되어 있습니다.
> > 2. 해당 디렉토리에서 make 명령어를 수행하면 lib디렉토리에 libICrypto.so 공유라이브러리를 생성합니다.
> > > 3. make clean 명령어로 so파일을 만들 때 생성되었던 오브젝트 파일을 지울 수 있습니다.


* doc
> * 이 디렉토리에는 라이브러리의 설명을 볼 수 있는 html디렉토리가 압축되어 들어있습니다.
> > * Doxygen 디렉토리에서 바로 html을 만들면 압축이 안되는 상태이기 때문에 직접 압축하였습니다.


* sample
> 1. i_crypto_library를 어떻게 사용하는지에 대한 예시 코드입니다.
> > 2. 해당 디렉토리에서 make 명령어 수행
> > > 3. make test 명령어로 실행파일 실행
> > > > 4. 결과를 확인하고 암호화, 복호화가 잘 되었는지 체크할 수 있습니다.
> > > > > 5. make clean으로 실행파일과 오브젝트 파일을 삭제할 수 있습니다.
<hr/>


## i_crypto에 대한 설명


> * 이 라이브러리는 암복호화에 필요한 인터페이스를 제공하며 openssl이용하여 구현되었습니다.
> * 함수 이름 앞에 i 키워드는 코드 작성자의 시그니처 prefix입니다.
> > * rsa관련 세 개의 함수는 참고자료에서 가져왔으며, 때문에 시그니처인 i를 붙이지 않았습니다.
> * 블록암호운용모드는 openssl의 ecb함수만을 이용하여 cbc모드, ctr모드를 구현하였습니다.
> * 한번에 데이터를 암복호화하는 i_enc, i_dec와 단계별로 처리하는 init, update, final 인터페이스도 제공합니다.
> * 이 라이브러리는 외부에 공개해도 될 인터페이스와 그렇지 않은 인터페이스를 구분합니다.
> > 1. include의 헤더파일에 작성되어있는 함수 헤더는 외부에 공개되는 인터페이스 입니다.
> > > * (1) 라이브러리 사용자는 헤더파일에 있는 함수 헤더와 주석, 또는 doc디렉토리에서 제공하는 문서를 통해 인터페이스 사용법을 익힐 수 있습니다.
> > > * (2) 헤더파일에 명시된 공개되는 인터페이스는 I_EXPORT키워드가 앞에 붙습니다.
> > 2. src 디렉토리에 c코드는 실제 고객에게 전달할 때는 내부 구현을 보여주지 않기 위해 제공하지 않습니다
> > > * (1) 이 i_crypto.c 코드에서 내부에서만 사용되고 외부로는 제공하지 않는 함수들이 존재합니다.
> > > * (2) 이러한 인터페이스는 앞에 I_LOCAL 키워드가 붙습니다.
> > > * (3) 사용자가 멤버 변수에 접근해서는 안되는 context구조체의 정의 또한 c코드에만 존재하고 헤더에 존재하지 않습니다.
<hr/>


## 사용시 주의사항


> * 현재 대칭키 암호 알고리즘은 AES128만을 제공합니다.
> * openssl의 cbc_encrypt같은 경우 기본적으로 제로패딩이지만 i_crypto는 pkcs방식을 이용합니다.
> * 블록암호운용모드는 cbc와 ctr모드 두 개만 제공합니다.
> * AES_set_key로 키를 생성할 때 파라미터로 들어가는 키 바이트 배열은 편의상 0으로 세팅하였습니다. 실제로는 적절한 키 값을 넣어야 합니다.
<hr/>


### Thank You For Reading Me!!!
