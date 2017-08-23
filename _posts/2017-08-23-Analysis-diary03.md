---
layout: post
title: "물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(3)"
date: 2017-08-23
author: conchi
categories: Malware Analysis
---

글이 상당히 뛰엄뛰엄 올라오는건... 기분탓이었으면 싶지만 실화인듯 하다. 언제쯤 1일 1포스팅을 할 수 있을까...(멍...)  
ㅜㅜ..작년여름에는 일하느라 사무실에 있어서 몰랐는데 난 더위에 넘나 쉽게 흐물해지는 물꼬기였다. 그래서 7월달에  미뤄덨던 사람들을 8월에 몰아서 보다보니 더 망나니같이 지내고 있는건 아닐까.. (라고 핑계를 대본다 딩딩)  
<br>

 모 무튼 얘랑 빨리 헤어지고싶다. ~~지겨워 죽겠다 뻐큐~~  
 대충보고 넘어가고싶은디..  "정리해야지~" 할때마다 아깐 안보였던것들이 자꾸 보이면서 발목을 잡는다. 진짜 부들부들쓰  
 이 맛에 ㅜㅜ.. 분석을 하는거지!!! ㅜㅜ 하면서도ㅜㅜ..  
 ~~그나저나 오버워치 플레 언제가지 이번시즌은 망한건가~~   
 <br>

 - 지난글 보러가기   
 [> 물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(1)](https://conchiholic.github.io/malware/analysis/2017/08/09/Analysis-diary01.html)    
  [> 물꼬기의 수상한 Analysis 일지 01 - 3.4 DDoS(2)](https://conchiholic.github.io/malware/analysis/2017/08/19/Analysis-diary02.html)   
<br>

- - -
#### 02. sub_100013E0()  
에 대해서 좀 더 이야기 해보자 한다. 두개의 쓰레드가 존재했었고, 첫번째 쓰레드의 기능을 알아보다가 끝! 오버워치하러감 수고링! 이러고 떠난것 같다. 첫번째 쓰레드에서는  파일의 확장자를 겁내 찾아댕긴다고 그랬다. 찾아댕긴다음에 뭔짓을 하는지 좀 더 분석해보았다. (지금은 그냥 기능 위주로 분석중이지만, 전체적인 분석이 끝나면 개요도를 그려볼 생각이다 너무 정신없다 ㅜㅜ)   
<br>

**첫번째 쓰레드**
<br>

![1](/assets/ana03/01.JPG)   
+)지난 글에서는 언급조차 안했던 부분이 있어서 추가한다.  
파일의 확장자를 찾기 전에 조건문을 타고 파일들을 부수는 함수로 들어가는데, 이때 Windows가 설치된 경로와 Program Files 의 경로는 제외시킨다.  
<br>

**cab_encry_10001810**   
이 안에서 파일의 확장자를 찾고, 원하는 확장자를 찾으면 파일을 부수는(?) 기능을 한다고 지난 포스팅에서 간단하게 언급했다. 실제로 이렇게 자세한 부분들이 필드에서 도움이 될지는 나도 잘 모르겠지만 ;ㅁ;.. 그냥 취업준비 하면서 공부하는 입장에서 쓰는거니 이것저것 닥치는대로 다 찾아보기로 했다.  
<br>

![1](/assets/ana03/05.JPG)     
이 함수안에서는 먼저 파일의 사이즈를 체크한다. 그리고 해당 파일의 크기가 4MB보다 큰지 작은지 확인한다. 파일의 크기가 4MB보다 작은경우, 기준값을 파일 크기로 바꿔버린다(해당 코드에서는 4MB를 기준으로 삼고있다) 이렇게 기준 값의 크기만큼 메모리에 동적할당 해주고, 해당 영역을 0으로 초기화 시켜버린다.
<br>

그리고는 WriteFile()로 파일을 0으로 푸쾈푸쾈 수고링쓰..     
이때  4MB씩 쪼개서 0으로 만드는 반복문을 포함한다.  
![1](/assets/ana03/02.JPG)      
<br>

![1](/assets/ana03/06.JPG)    
그리고 그 파일의 크기가 10mb를 넘지 않는경우, .cab파일로 만들어버리며 모든 작업들이 끝나면 깔끔하게 원본 파일을 삭-제 한다.(ㄹㅇ 혼파망)  
<br>

![1](/assets/ana03/03.JPG)      
<br>

하지만 끔찍한 일은 여기서 끝이 아니다.  
두번째 Thread에서도 이에 버금가는 끔찍한 행위가 일어난다.  
<br>
<br>

**두번째 쓰레드**  
두번째 쓰레드 안으로 들어오면 가장 처음 만날 수 있는 함수를 분석해보았다.  
<br>

**mbr_destruction_10001C70**
이름은 이렇게 지어줬다.  
![1](/assets/ana03/04.JPG)   
코드는 다음과 같다. Windows버전을 체크한다(자세한 내용은 링크를 첨부한다.)  
  [> 참고링크 : msdn ](https://msdn.microsoft.com/ko-kr/library/windows/desktop/ms724834(v=vs.85).aspx)   
  <br>

  요 링크내용을 토대로   
`VersionInformation.dwPlatformId == 2`   
- Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003, Windows XP, or Windows 2000  
<br>

`VersionInformation.dwMajorVersion == 6`  
- Windows 10과 Windows Server 2016은  dwMajorVersion가 10, Windows Vista 이하의 버전은  dwMajorVersion가 5이다.
<br>

이 조건을 하나라도 만족하거든 v1에는 512 가 들어가고 그렇지 않은 경우에는 v1에는 0x400000이 들어간다.  
<br>

v1에 512가 들어가는걸 보고 mbr과 관련된 부분이 아닐까 짐작할 수 있었다. 그다음에 나오는 a_Physicaldrive는
`unicode 0, <\\.\PhysicalDrive%d>,0` 이런 데이터들을 담고 있었다. 대놓고 걍 mbr부수러감 수고링 하는듯했다. mbr영역을 비롯하여 PhysicalDrive영역을 0으로 열심히 만드는 기능이 들어있는 끔찍한녀석이었다.
+) PhysicalDrive의 0부터 25까지 반복문을 통해 계속해서 안의 데이터들을 부순다.

- - -
딩딩 모르겠당 릴리릴리  
