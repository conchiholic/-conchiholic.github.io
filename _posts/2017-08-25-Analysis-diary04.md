---
layout: post
title: "물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(4)"
date: 2017-08-25
author: conchi
categories: Malware Analysis
---


 어디까지했더라..  
 정신이 혼미해지기 시작한다 흑흑.. ㅜㅜ  

 - **지난글 보러가기**   
 [> 물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(1)](https://conchiholic.github.io/malware/analysis/2017/08/09/Analysis-diary01.html)    
  [> 물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(2)](https://conchiholic.github.io/malware/analysis/2017/08/19/Analysis-diary02.html)   
    [> 물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(3)](https://conchiholic.github.io/malware/analysis/2017/08/23/Analysis-diary03.html)   
<br>

- - -

![1](/assets/ana04/01.JPG)   
그동안 분석한 sfofsvc.dll(sxxxsvc.dll)의 분석한 부분들에 대한 개요를 간단하게 그려봤다. 이번글에서는 Time_10001200()를 분석해볼까 한다.  
<br>

우선 해당 함수에서는 `noise03.dat` 파일을 체크한다. IDA로 보면 해당 파일의 이름이 보이지 않는데 뭔가 간단해보이지만 복잡(?)해보이는 루틴을 타고 의문의 데이터들이 `noise03.dat` 라는 이름으로 재탄생한다.
<br>

![1](/assets/ana04/03.JPG)   
이렇게 생겼는데 헥사값을 확인해도 뭐 도통 뭔지 모르겠다. 이럴땐 모다? 동적분석이 필요하다 'ㅅ'/  
<br>

이녀석 또한 dll이라 분석할 때는 지난 1편에서 했듯이 rundll32.dll에 붙여서 사용해도 되지만, 요번에는 그당시 받았던 피드백에 있던 다른 방법을 이용하여 해당 구문까지 이동하였다.  
<br>

ollydbg에서 뭐 아무런 설정없이 dll을 로드하면 dll이 로드되긴 한다. 그런데 트레이싱을 해보면 내가 분석중인 코드가 아닌 영 엉뚱한곳으로 이동하고, 그쪽에서 뭔가 모를것들이 실행되는게 보인다(전혀 내가 생각하던 주소값이 아닌 부분이 등장한다)  
<br>

여긴어딘가 싶어서 ida로 dll을 열어놓고 ollydbg에 보이는 주소를 계산해서 찾아갔더니 역시나 dllmain의 부분이 등장했다. but 현재는 dllmain과는 상관없는곳이 궁금하기 때문에 해당 dll을 ollydbg에서 다시 실행한 후, 아무곳에다가 `JMP 내가원하는위치의 주소` 이런식의 장치를 박은 후 실행하여 강제로 이동하게끔 만들었다. 정말 손쉽게 원하는 부분까지 이동하였고 그곳에서 디버깅을 진행하였다.(뿌-듯)
<br>

IDA에서 뷁뷁 거리던 부분을 사용하는 루틴으로 이동하여 반복문을 몇번 진행하였더니 이런 문자열이 등장하였다.  
![1](/assets/ana04/02.JPG)   

Host.dll에서 떨어졌던 파일중 하나였고, 이녀석을 이용하는구나 알 수 있게 되었다.
<br>

time_10001200()에서 일어나는 일은 다음과 같다.  
<br>

![1](/assets/ana04/04.JPG)    
<br>

![1](/assets/ana04/05.JPG)   
noise03.dat파일이 열리지 않으면(or 없는경우) 1을 return한다.  
<br>

![1](/assets/ana04/06.JPG)   
localtime과 noise03.dat에 적힌 시간을 비교하여 이 시간이 localtime 보다 큰 경우에도 1을 return 한다.  
<br>

그래서 return 1을 하면 모다
![1](/assets/ana04/07.JPG)   
바로 sub_100013E0()함수를 타게되고 그러면 파일들과 mbr이 수고링 당한다. 키듀키듀  
<br>
<br>

- - -
이렇게 멀고 험난했던 sxxxsvc.dll 분석도 어째 끝이 난듯하다.  
딩딩'ㅅ'/  
메르시 원챔인데... 패치어쩌냐... (눈물)  
