# 3D Action Game

**상태 패턴 기반 캐릭터 제어와 맵 최적화를 다룬 Unity 3D 액션 게임**

![Unity](https://img.shields.io/badge/Unity_6-000000?style=flat-square&logo=unity&logoColor=white)
![C Sharp](https://img.shields.io/badge/C%23-512BD4?style=flat-square&logo=csharp&logoColor=white)
![AI Navigation](https://img.shields.io/badge/AI_Navigation-166534?style=flat-square)
![ProBuilder](https://img.shields.io/badge/ProBuilder-334155?style=flat-square)

<!-- TODO: 플레이 GIF 또는 스크린샷 2~3장 -->

## 프로젝트 소개

방을 이동하며 적을 처치하고 진행하는 3인칭 액션 게임입니다. 개인 프로젝트로 진행했으며, 캐릭터 상태 관리 구조와 맵 최적화를 중심 주제로 삼았습니다.

<!-- TODO: 개발 기간 -->

## 주요 구현

| 영역 | 내용 |
|---|---|
| 캐릭터 제어 | 플레이어·적 각각의 상태 기계, 이동·점프·공격·피격·사망 |
| 적 AI | NavMesh 기반 순찰·추격·공격, 사망 시 Ragdoll 전환 |
| 무기 | 옵저버 패턴 기반 타격 판정 전달 |
| 맵 | 방 단위 활성화 관리, 스테이지 분할, 문 상호작용 |
| UI | 체력 바, 로딩 패널 |
| 에디터 | 플레이어 컨트롤러 커스텀 인스퀥터 |

## 기술적 포인트

**상태 패턴 + StateMachineBehaviour 병행**
캐릭터 상태 전환은 `ICharacterState` 구현체로 관리하고, 애니메이션 클립에 맞춰 발생해야 하는 처리(공격 판정 활성화, 피격 경직)는 Unity의 StateMachineBehaviour로 분리했습니다. 상태 로직과 애니메이션 타이밍을 각자의 자리에서 다루도록 나눈 구성입니다.

**옵저버 패턴으로 무기와 캐릭터 분리**
무기가 대상을 직접 참조하지 않고 `IWeaponObservable` / `IWeaponObserver`로 타격 이벤트만 알립니다. 무기를 추가하거나 교체할 때 캐릭터 코드를 수정하지 않습니다.

**맵 최적화**
스테이지가 커지면서 프레임이 떨어져 아래 작업을 진행했습니다.

- 오클루전 컬링 적용
- 라이트맵 베이크
- 스테이지 분할 (Stage02 → Stage02-1)
- 방 단위 오브젝트 활성화 관리로 비활성 구역 연산 제거
- Memory Profiler로 병목 확인

<!-- TODO: 최적화 전후 수치. 프레임, 드로우콜, 배치 수 중 기억나는 것 아무거나 -->

## 기술 스택

Unity 6000.2.6f2 · C# · Input System · AI Navigation · ProBuilder · Polybrush · DOTween · Memory Profiler

## 실행 방법

1. Unity Hub에서 저장소 루트를 프로젝트로 추가합니다. (Unity 6000.2.6f2)
2. `Assets/01. Scenes/Stage01.unity`를 엽니다.
3. Play Mode에서 실행합니다.

## 프로젝트 구조

```text
Assets/
├── 01. Scenes/          # 스테이지 씬
└── 02. Scripts/
    ├── Common/          # 게임 매니저, 상태 인터페이스, 유틸
    ├── Player/          # 플레이어 컨트롤러, State, SMB
    ├── Enemy/           # 적 컨트롤러, State, SMB, 체력 바
    ├── Weapon/          # 옵저버 기반 타격 판정
    ├── Room/            # 방 단위 활성화 관리
    ├── Prop/            # 문 등 상호작용 오브젝트
    ├── UI/              # 체력 바, 로딩 패널
    └── Editor/          # 커스텀 인스펙터
```
