# FASTFUNC Native Analyzer (Rust)

`Plan.md`/`Plan2.md`의 Cloud Analyzer를 **네이티브 성능(Rust)** 으로 구현한 MVP입니다.

## 핵심 방향
- Collector(Windows PT/TTD)는 별도
- Analyzer는 번들 포맷(`meta.json`, `module_map.json`, `trace_events.jsonl`)만 신뢰
- 디렉터리/ZIP 번들 모두 지원
- 스레드별 call stack을 유지해 `api/syscall/exception` 이벤트를 **현재 활성 함수(top-of-stack)** 에 귀속

## 구현 단계
1. Ingest & Index: 번들 루트 해석, 메타/모듈맵/이벤트 스트림 로드
2. Address Normalize: 주소를 `(module, rva)` 기반으로 정규화
3. Callstack Attribution: 스레드별 call/ret을 따라 API 이벤트를 함수 단위로 귀속
4. Callgraph: call edge 카운트, hotness/fan-in/fan-out 집계
5. CFG features: indirect/jumptable/switch-like/flattening/opaque 징후 계산
6. Behavior timeline: 귀속된 함수 기준 API 타임라인 생성
7. Semantic labels(rule-based): file/reg/net 등 라벨 및 근거 생성
8. Report: `analysis/*.json*`, `reports/report.json`, `reports/report.md` 출력

## 실행
```bash
cargo run -- tests/fixtures/bundle --out out_fastfunc --top 20
```

ZIP 예시:
```bash
cargo run -- artifact_bundle_sample.zip --out out_fastfunc_zip --top 20
```

## 테스트
```bash
cargo test
```

## 출력 파일
기본:
- `analysis/state_ingest.json`
- `analysis/addr_norm.jsonl`
- `analysis/callgraph.json`
- `analysis/cfg_features.jsonl`
- `analysis/behavior_timeline.jsonl`
- `analysis/function_labels.jsonl`
- `reports/report.json`
- `reports/report.md`

호환(v2 스타일):
- `fastfunc.report.json`
- `fastfunc.report.md`
