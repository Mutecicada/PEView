## 문제 상황 
- PEView를 만들던 중 특정 파일만의 섹션헤더만 읽히지 않는 오류가 생겼다.  

- fread() 함수가 파일을 읽다가 중간부분에서 더 이상 읽히지 않는 문제가 생겼다.<br> 해결하기 위해 fseek로 위치도 재조정해보고 한바이트씩도 읽어보고 여러가지 시도를 해보았지만 제대로 되지 않았다.

- HxD로 파일을 까보고 buffer를 직접 대조해보면서 확인해 보다가 항상 같은 부분에서 fread()가 멈춘다는 사실을 알게 되었다.

## 문제 원인
- 원인은 바로 파일안에 `'1A'`라는 데이터가 포함되어 있었던 것이다.

- 아스키 코드 표에서 `'1A'`라는 값은 `Substitute`라는 값을 가지는 [제어 문자표](https://ko.wikipedia.org/wiki/ASCII#%EC%A0%9C%EC%96%B4_%EB%AC%B8%EC%9E%90%ED%91%9C) 이다.	

- '1A'라는 값은 파일의 끝을 의미하는 `'EOF'`로 사용되거나 [Ctrl] + [z]를 누르면 키보드가 이 코드를 전송하게 사용됩니다.

- 한 마디로 fread가 읽다가 '1A'라는 값을 보고 파일의 끝이라고 인식해서  더 이상 읽지 않았던 것이다.

- '1A' 외에도 제어 문자표에 있는 문자가 나오면 문제가 있을 것이라고 생각한다.

## 해결 방법 
- 해결 방법은 간단하다. '1A'라는 데이터를 텍스트를 보지 않고 바이너리로 보면 된다.

- fopen을 할 때, 'r' 모드로 여는 것이아닌 'rb'모드로 여는 것이다.