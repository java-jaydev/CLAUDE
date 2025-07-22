# Spring Boot Documentation Structure

이 디렉토리는 Spring Boot 프로젝트의 상세한 개발 가이드를 모듈화하여 관리합니다.

## 📁 문서 구조

### 📋 [spring-patterns.md](spring-patterns.md)
**Spring Boot 패턴 및 설계 원칙**
- DTO 패턴 가이드라인 (네이밍, 구조, Validation)
- Repository 패턴 (JPA Repository, QueryDSL Custom Repository)
- Service 패턴 (Transaction 관리, 도메인 서비스 분리)
- Controller 패턴 (REST API 설계, 응답 표준화)
- Entity 패턴 (BaseEntity, 도메인 설계, Enum 활용)
- Best Practices 및 성능 고려사항

### 💻 [spring-examples.md](spring-examples.md)
**실제 코드 구현 예시**
- 완전한 Controller 구현 (CRUD, 페이징, 검증)
- Service Layer 구현 (비즈니스 로직, Transaction)
- Entity 및 Enum 구현 (BaseEntity 상속, Converter)
- QueryDSL Repository 구현체 (동적 쿼리, 프로젝션)
- Security 설정 (SecurityFilterChain, JWT Filter, Handler)
- Exception Handler 구현 (글로벌 예외 처리)
- HTTP 상태 코드 처리 (성공/오류 응답)
- RESTful API 설계 원칙

### ⚙️ [spring-config.md](spring-config.md)
**환경 설정 및 성능 최적화**
- 환경별 설정 관리 (@ConfigurationProperties, 프로파일)
- application.yml 환경별 설정 (dev, prod, test)
- 민감정보 환경변수 처리 (Docker, Kubernetes)
- 성능 최적화 전략
  - JPA 성능 최적화 (배치 처리, N+1 해결, 페이징)
  - Connection Pool 최적화 (HikariCP)
  - Redis 캐싱 전략
  - QueryDSL 성능 최적화 (프로젝션, 서브쿼리)
  - 데이터베이스 인덱스 전략
- 보안 설정 (CORS, JWT, 암호화)
- 프로파일 관리 및 빌드 설정
- Docker 환경 설정
- 로깅 설정 (환경별, Logback)

### 🧪 [testing-guide.md](testing-guide.md)
**테스트 전략 및 구현**
- 테스트 전략 (Unit, Integration, Web Layer, E2E)
- 테스트 환경 설정 (프로파일, Base 클래스)
- Unit Test 예시
  - Service Layer Test (Mockito, ArgumentCaptor)
  - Repository Test (@DataJpaTest)
- Integration Test 예시
  - Repository Integration Test
  - QueryDSL Repository Test
- Web Layer Test
  - Controller Test (@WebMvcTest)
  - Security Test (인증/인가)
- TestContainers 통합 테스트 (PostgreSQL, Redis)
- 성능 테스트 (JMeter 연계)
- 테스트 데이터 관리 (Fixtures, ObjectMother)
- 테스트 최적화 및 Best Practices

### 📊 [monitoring-api.md](monitoring-api.md)
**모니터링, API 문서화, 에러 관리**
- **모니터링 및 로깅**
  - 로깅 전략 (구조화된 로깅, JSON 형식)
  - Health Check 설정 (Actuator, 커스텀 Indicator)
  - 메트릭 수집 (Micrometer, 커스텀 메트릭)
  - 분산 추적 (Zipkin/Jaeger)
- **API 문서화**
  - SpringDoc OpenAPI 3 설정
  - Controller 문서화 (@Tag, @Operation, @ApiResponse)
  - DTO 문서화 (@Schema, examples)
  - API 버전 관리 문서화
- **에러 코드 정의 및 관리**
  - 표준 에러 코드 체계 (카테고리별 분류)
  - 커스텀 예외 클래스 (BusinessException 계열)
  - 글로벌 예외 처리 (통합 Exception Handler)
  - 에러 응답 표준화 (CommonResponse 개선)
  - 에러 코드 문서화 (자동 생성)
- **모니터링 알림**
  - 로그 기반 알림
  - 메트릭 기반 모니터링

## 🎯 사용 가이드

### 📖 문서 참조 방법

1. **새 프로젝트 시작**: `spring-config.md` → `spring-patterns.md`
2. **기능 개발**: `spring-patterns.md` → `spring-examples.md` → `testing-guide.md`
3. **API 문서화**: `monitoring-api.md` (API 문서화 섹션)
4. **에러 처리**: `monitoring-api.md` (에러 코드 정의 섹션)
5. **성능 최적화**: `spring-config.md` (성능 최적화 섹션)
6. **테스트 작성**: `testing-guide.md`
7. **운영 환경 설정**: `spring-config.md` + `monitoring-api.md`

### 🔄 문서 업데이트 가이드

- **새로운 패턴 추가**: `spring-patterns.md` 업데이트
- **코드 예시 추가**: `spring-examples.md` 업데이트  
- **설정 변경**: `spring-config.md` 업데이트
- **테스트 전략 변경**: `testing-guide.md` 업데이트
- **모니터링/API 변경**: `monitoring-api.md` 업데이트

### 📏 문서 크기 관리

- **목표**: 각 문서 20k 문자 이하 유지
- **분리 기준**: 기능별, 계층별 분리
- **중복 제거**: 공통 내용은 메인 CLAUDE.md에서 관리

## 🔗 연관 관계

```
CLAUDE.md (메인)
├── 기본 설정 → spring-config.md
├── 패턴 가이드 → spring-patterns.md
├── 구현 예시 → spring-examples.md
├── 테스트 → testing-guide.md
└── 운영 → monitoring-api.md

spring-patterns.md
├── 패턴 정의
└── 구체적 구현 → spring-examples.md

spring-examples.md
├── 코드 예시
├── 설정 참조 → spring-config.md
└── 테스트 예시 → testing-guide.md

spring-config.md
├── 환경 설정
├── 성능 최적화
└── 모니터링 연계 → monitoring-api.md

testing-guide.md
├── 테스트 전략
└── 패턴 활용 → spring-patterns.md

monitoring-api.md
├── 모니터링
├── API 문서화
└── 에러 관리
```

## 🎛️ AI 참조 최적화

이 모듈화된 구조는 AI가 다음과 같이 효율적으로 정보에 접근할 수 있도록 설계되었습니다:

1. **선택적 로딩**: 필요한 문서만 로드하여 처리 속도 향상
2. **컨텍스트 집중**: 특정 주제에 집중된 정보로 정확도 향상  
3. **계층적 접근**: 메인 문서에서 시작하여 필요시 상세 문서 참조
4. **상호 참조**: 문서 간 명확한 참조 관계로 일관성 유지

이를 통해 57.8k 문자의 단일 파일에서 발생하던 성능 이슈를 해결하면서도 정보의 품질과 완성도는 그대로 유지합니다.