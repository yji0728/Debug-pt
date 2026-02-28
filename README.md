# Reverse Optimization Machine

`Plan.md`, `Plan2.md`의 방향(브레이크포인트 중심이 아닌 트레이스/규칙엔진/리플레이 중심)을 바로 실행 가능한 형태로 만든 작은 CLI 머신입니다.

## 핵심 아이디어

1. **분기 이벤트를 스트리밍으로 수집** (JSONL 입력)
2. **함수 단위 통계 + 규칙 점수화**
3. **핫스팟 우선순위 도출**
4. **리플레이/스냅샷 기반 분기 다이버전스 액션 제안**

## 입력 포맷(JSONL)

한 줄당 이벤트 1개:

```json
{"type":"branch","ip":"0x401000","target":"0x401020","func":"sub_401000"}
{"type":"indirect_jump","ip":"0x401020","target":"0x407000","func":"sub_401000"}
```

지원 이벤트 타입:
- `branch`
- `call`
- `ret`
- `indirect_jump`
- `mem_write`

## 사용법

```bash
python3 src/reversing_machine.py sample_trace.jsonl -k 5 -o hotspots.json
```

## 출력

- `machine`: 버전/머신 이름
- `strategy`: Plan 문서의 핵심 전략
- `hotspots`: 함수별 점수, 태그, 다음 액션(리플레이 + 분기 유도)

## 빠른 시작 샘플

```bash
python3 src/reversing_machine.py examples/sample_trace.jsonl -k 3
```
