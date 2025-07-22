# Spring Boot Development Guide with Claude

이 저장소는 Spring Boot 프로젝트 개발을 위한 포괄적인 가이드 문서를 제공합니다. Claude AI를 활용한 효율적인 개발 워크플로우와 Spring Boot 베스트 프랙티스가 포함되어 있습니다.

## 📋 문서 구조

### 🎯 [CLAUDE.md](CLAUDE.md) - 메인 설정 파일
Claude AI를 위한 프로젝트 설정 및 가이드라인
- 프로젝트 개요 및 기술 스택
- Spring Boot 프로젝트 초기 설정 (Spring Initializr 활용)
- 코딩 스타일 & 컨벤션
- Database 컨벤션
- Claude의 역할 및 책임

### 📁 docs/ - 상세 개발 가이드

#### 📋 [spring-patterns.md](docs/spring-patterns.md) - Spring Boot 패턴 가이드
- DTO 패턴 가이드라인 (네이밍, 구조, Validation)
- Repository 패턴 (JPA Repository, QueryDSL Custom Repository)
- Service 패턴 (Transaction 관리, 도메인 서비스 분리)
- Controller 패턴 (REST API 설계, 응답 표준화)
- Entity 패턴 (BaseEntity/BaseTimeEntity, 도메인 설계, Enum 활용)

#### 💻 [spring-examples.md](docs/spring-examples.md) - 코드 구현 예시
- 완전한 Controller 구현 (CRUD, 페이징, 검증)
- Service Layer 구현 (비즈니스 로직, Transaction)
- Entity 및 Enum 구현 (BaseEntity 상속, Converter)
- QueryDSL Repository 구현체 (동적 쿼리, 프로젝션)
- Security 설정 (SecurityFilterChain, JWT Filter, Handler)
- Exception Handler 구현 (글로벌 예외 처리)

#### ⚙️ [spring-config.md](docs/spring-config.md) - 환경 설정 및 최적화
- 환경별 설정 관리 (@ConfigurationProperties, 프로파일)
- application.yml 환경별 설정 (dev, prod, test)
- 성능 최적화 전략 (JPA, Connection Pool, Redis, QueryDSL)
- 보안 설정 (CORS, JWT, 암호화)
- Docker 환경 설정

#### 🧪 [testing-guide.md](docs/testing-guide.md) - 테스트 전략
- 테스트 전략 (Unit, Integration, Web Layer, E2E)
- Unit Test 예시 (Service, Repository)
- Integration Test 예시 (TestContainers)
- Web Layer Test (Controller, Security)
- 성능 테스트 및 테스트 데이터 관리

#### 📊 [monitoring-api.md](docs/monitoring-api.md) - 모니터링 & API 문서화
- 로깅 전략 및 설정
- Health Check 및 Actuator 설정
- SpringDoc OpenAPI 3 설정
- API 문서화 (Controller, DTO)
- 에러 코드 정의 및 관리
- 글로벌 예외 처리

## 🔧 Claude 설정

이 프로젝트를 Claude Code와 함께 사용하려면:

1. `.claude.example/settings.example.json`을 참고하여 개인 설정 생성
2. `.claude/settings.local.json` 파일로 복사하여 개인 환경에 맞게 수정
3. `CLAUDE.md` 파일이 프로젝트 가이드로 자동 로드됨

**참고**: `.claude/` 폴더는 개인 설정이므로 Git에서 제외됩니다.

## 🚀 기술 스택

### Core Framework
- **Spring Boot 3.x** - 메인 프레임워크
- **Java 17+** - 프로그래밍 언어
- **Gradle 8.x** - 빌드 도구

### Database & ORM
- **PostgreSQL** (Production) / **H2** (Test)
- **Spring Data JPA** & **Hibernate 6.x**
- **QueryDSL 5.x** - 타입 안전한 동적 쿼리

### Security & Validation
- **Spring Security 6.x**
- **JWT** - 인증/인가
- **Spring Boot Validation** (Bean Validation 3.0)

### Documentation & Testing
- **SpringDoc OpenAPI 3** (Swagger UI)
- **JUnit 5** & **Mockito**
- **TestContainers** - 통합 테스트

### Monitoring
- **Spring Boot Actuator**
- **Micrometer** - 메트릭 수집

## 🎯 사용법

### 새 프로젝트 시작
1. [Spring Initializr](https://start.spring.io/)에서 기본 설정으로 프로젝트 생성
2. `docs/spring-config.md` 참조하여 환경별 설정 파일 생성
3. `docs/spring-patterns.md` 참조하여 BaseEntity 및 기본 구조 설정

### 새 기능 개발
1. `docs/spring-patterns.md` 참조하여 Entity, DTO, Repository 설계
2. `docs/spring-examples.md` 참조하여 Controller, Service 구현
3. `docs/testing-guide.md` 참조하여 테스트 코드 작성

### API 문서화
1. `docs/monitoring-api.md` 참조하여 OpenAPI 애노테이션 추가
2. Controller에 @Tag, @Operation 애노테이션 적용
3. DTO에 @Schema 애노테이션으로 상세 설명 추가

## 🔄 문서 특징

### AI 최적화 구조
- **선택적 로딩**: 필요한 문서만 로드하여 처리 속도 향상
- **컨텍스트 집중**: 특정 주제에 집중된 정보로 정확도 향상  
- **계층적 접근**: 메인 문서에서 시작하여 필요시 상세 문서 참조
- **상호 참조**: 문서 간 명확한 참조 관계로 일관성 유지

### 핵심 원칙
- **이너클래스 금지** - 모든 클래스는 별도 파일로 분리
- **BaseEntity 이원화** - BaseTimeEntity(시간만) / BaseEntity(완전한 감사)
- **CommonResponse 표준화** - 일관된 API 응답 구조
- **코딩 스타일 통일** - Lombok, 네이밍, 애노테이션 일관성

## 📖 기여 가이드

문서 개선 사항이나 새로운 패턴 추가 시:
1. 기존 문서 구조와 스타일을 따라주세요
2. 코드 예시는 실제 동작하는 완전한 코드로 제공해주세요
3. 각 패턴에 대한 사용 시나리오와 주의사항을 함께 작성해주세요

## 📝 License

이 문서는 교육 및 참고 목적으로 자유롭게 사용하실 수 있습니다.