# Claude Assistant Configuration for SpringBoot Project

## Project Overview

이 프로젝트는 Java SpringBoot를 기반으로 한 웹 애플리케이션입니다.

## 프로젝트 초기 설정

### Spring Initializr를 이용한 프로젝트 생성

새로운 Spring Boot 프로젝트는 반드시 **[Spring Initializr](https://start.spring.io/)**를 사용하여 생성합니다.

#### 기본 설정

- **Project**: Gradle - Groovy
- **Language**: Java
- **Spring Boot**: 3.2.x (최신 안정 버전)
- **Project Metadata**:
  - Group: `net.thetelos` (또는 회사 도메인)
  - Artifact: `project-name`
  - Name: `project-name`
  - Description: 프로젝트 설명
  - Package name: `net.thetelos.projectname`
  - Packaging: Jar
  - Java: 17

#### 필수 Dependencies

**Core**
- Spring Web
- Spring Data JPA
- Spring Security
- Validation

**Database**
- PostgreSQL Driver (운영 환경)
- H2 Database (테스트 환경)

**Development Tools**
- Spring Boot DevTools
- Lombok
- Spring Configuration Processor

**Monitoring & Documentation**
- Spring Boot Actuator

#### 추가 설정이 필요한 Dependencies

프로젝트 생성 후 수동으로 추가해야 하는 의존성들:

```gradle
dependencies {
    // QueryDSL (LTS 버전)
    implementation 'com.querydsl:querydsl-jpa:5.0.0:jakarta'
    annotationProcessor 'com.querydsl:querydsl-apt:5.0.0:jakarta'

    // SpringDoc OpenAPI (Swagger)
    implementation 'org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0'

    // JWT (LTS 버전)
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'

    // TestContainers (테스트용)
    testImplementation 'org.testcontainers:junit-jupiter:1.19.3'
    testImplementation 'org.testcontainers:postgresql:1.19.3'
}
```

### Tech Stack

- **Framework**: Spring Boot 3.x
- **Language**: Java 17+
- **Build Tool**: Gradle 8.x
- **Database**: PostgreSQL (Production), H2 (Test)
- **ORM**: Spring Data JPA, Hibernate 6.x
- **Query DSL**: QueryDSL 5.x (Type-safe queries)
- **Security**: Spring Security 6.x
- **Cache**: Redis (Session & Cache Management)
- **Validation**: Spring Boot Validation (Bean Validation 3.0)
- **JSON Processing**: Jackson
- **Testing**: JUnit 5, Mockito, TestContainers, Spring Boot Test
- **API Documentation**: SpringDoc OpenAPI 3 (Swagger UI)
- **Monitoring**: Spring Boot Actuator, Micrometer
- **Development Tools**: Lombok, Spring Boot DevTools

### Environment Profiles

- `dev`: 개발 환경
- `stg`: 스테이징 환경
- `prod`: 운영 환경
- `test`: 테스트 환경 (H2 DB 사용)

## Project Structure

```
src/
├── main/
│   ├── java/
│   │   └── net/thetelos/project/
│   │       ├── config/          # 설정 클래스
│   │       ├── controller/      # REST 컨트롤러
│   │       ├── service/         # 비즈니스 로직
│   │       ├── repository/      # 데이터 액세스 레이어
│   │       │   └── querydsl/    # QueryDSL Repository 구현체
│   │       ├── entity/          # JPA 엔티티
│   │       ├── dto/             # 데이터 전송 객체
│   │       ├── enums/           # Enum 클래스들
│   │       ├── security/        # Spring Security 설정 및 관련 클래스
│   │       ├── common/          # 공통 응답, 상수 등
│   │       ├── aspect/          # AOP 관련 클래스
│   │       ├── exception/       # 예외 처리
│   │       └── util/            # 유틸리티 클래스
│   └── resources/
│       ├── application.yml      # 기본 설정
│       ├── application-dev.yml  # 개발 환경 설정
│       ├── application-stg.yml  # 스테이징 환경 설정
│       ├── application-prod.yml # 운영 환경 설정
│       └── application-test.yml # 테스트 환경 설정
└── test/
    └── java/
        └── net/thetelos/project/ # 테스트 코드
```

## Coding Standards & Conventions

### Java Code Style

- **네이밍 컨벤션**: camelCase (변수, 메서드), PascalCase (클래스), UPPER_SNAKE_CASE (상수)
- **패키지 네이밍**: 소문자, 점(.)으로 구분
- **Indentation**: 4 spaces (탭 사용 금지)
- **Line Length**: 최대 120자
- **Import**: static import는 일반 import 뒤에 배치
- **클래스 설계**: Inner Class(이너클래스) 사용 금지 - 별도 클래스 파일로 분리
- **Enum 선호**: 상수 관리 및 타입 안전성을 위해 Enum 적극 활용

### Spring Boot Best Practices

- `@RestController`와 `@Service`, `@Repository` 애노테이션 적극 활용
- Constructor Injection 우선 사용 (필드 주입 지양)
- `@Transactional` 적절한 위치에 배치
- 기본적으로 클래스에 @Transactional(readOnly = true)를 선언하고, 데이터의 변경(등록, 수정, 삭제)이 필요한 메서드에는 메서드 단위로 @Transactional을 별도 지정합니다.
- **QueryDSL 활용**: Repository 패턴과 QueryDSL Custom Repository 조합으로 타입 안전한 동적 쿼리 구현
- **Spring Security**: SecurityFilterChain 기반의 최신 Security 설정 (WebSecurityConfigurerAdapter 사용 금지)
- **Validation**: @Valid, @Validated를 활용한 요청 데이터 검증, 커스텀 Validator 구현
- **Exception Handling**: @ControllerAdvice와 @ExceptionHandler를 활용한 글로벌 예외 처리
- **API Response**: 표준 응답 형식(CommonResponse<T>) 사용으로 일관된 API 응답 구조 유지
- **로깅**: Lombok의 @Slf4j를 활용하여 처리, 민감정보 로깅 금지
- **Bean Validation 3.0**: @NotNull, @NotBlank, @Size 등 표준 Validation 애노테이션 활용
- **JPA Auditing**: @EnableJpaAuditing을 통한 감사 컬럼 자동 관리, BaseEntity/BaseTimeEntity 상속 구조 활용

### Database Conventions

- **테이블명**: snake_case
- **컬럼명**: snake_case
- **Primary Key**: `id` (Long 타입)
- **생성/수정 시간**: `created_at`, `updated_at`
- **소프트 삭제**: `deleted_at`
- **Index 네이밍**: `idx_테이블명_컬럼명` 형식 (예: idx_users_email)
- **Foreign Key**: `fk_테이블명_참조테이블명` 형식 (예: fk_orders_users)
- **JPA 애노테이션**: @Entity, @Table(name = "table_name"), @Column(name = "column_name") 명시적 사용
- **BaseEntity**: 공통 필드는 BaseEntity/BaseTimeEntity 상속으로 관리
  - BaseTimeEntity: 시간 추적만 (id, created_at, updated_at)
  - BaseEntity: 완전한 감사 추적 (BaseTimeEntity + created_by, updated_by)
- **감사(Audit) 컬럼**: JPA Auditing 활용하여 자동 입력
- **테이블 주석**: @Table의 comment 속성 또는 @Comment 애노테이션 활용으로 테이블/컬럼 설명 추가

## Claude's Role & Responsibilities

### 주요 작업 영역

1. **새로운 기능 개발**
   - REST API 엔드포인트 설계 및 구현
   - 비즈니스 로직 구현
   - 데이터베이스 스키마 설계
   - DTO 및 Entity 클래스 작성

2. **코드 리팩토링**
   - 코드 중복 제거
   - 성능 최적화
   - 가독성 향상
   - 디자인 패턴 적용

3. **버그 수정**
   - 예외 상황 분석 및 해결
   - 로직 오류 수정
   - 성능 이슈 해결

4. **API 설계**
   - RESTful API 설계 원칙 준수
   - HTTP 상태 코드 적절한 사용
   - 요청/응답 스키마 정의
   - API 문서화

5. **테스트 코드 작성**
   - Unit Test (JUnit 5, Mockito)
   - Integration Test
   - API Test
   - 테스트 커버리지 향상

6. **문서화**
   - 코드 주석 작성
   - README 업데이트
   - API 문서 작성
   - 아키텍처 문서 정리

### Communication Style

- 코드 리뷰시 건설적인 피드백 제공
- 복잡한 로직에 대한 명확한 설명
- 대안 솔루션 제시
- 베스트 프랙티스 공유

## 상세 가이드 문서

프로젝트의 상세한 구현 가이드는 다음 문서들을 참조하세요:

### 📋 [Spring Patterns Guide](docs/spring-patterns.md)
- DTO 패턴 가이드라인
- Repository 패턴 (JPA Repository, QueryDSL)
- Service 패턴
- Entity 설계 원칙
- Controller 패턴

### 💻 [Spring Examples](docs/spring-examples.md)
- 완전한 Controller 구현 예시
- Service Layer 구현 예시
- Entity 및 Enum 예시
- QueryDSL Repository 구현체
- Security 설정 예시
- Exception Handler 구현
- HTTP 상태 코드 처리

### ⚙️ [Spring Configuration](docs/spring-config.md)
- 환경별 설정 관리 (@ConfigurationProperties)
- application.yml 환경별 설정
- 민감정보 환경변수 처리
- 성능 최적화 (JPA, Connection Pool, Redis, QueryDSL)
- 데이터베이스 인덱스 전략
- 보안 설정

### 🧪 [Testing Guide](docs/testing-guide.md)
- 테스트 전략 및 환경 설정
- Unit Test 예시 (Service, Repository)
- Integration Test 예시
- Web Layer Test (Controller)
- TestContainers 통합 테스트
- 성능 테스트
- 테스트 데이터 관리

### 📊 [Monitoring & API Documentation](docs/monitoring-api.md)
- 로깅 전략 및 설정
- Health Check 및 Actuator 설정
- 메트릭 수집 (Micrometer)
- SpringDoc OpenAPI 3 설정
- API 문서화 (Controller, DTO)
- 에러 코드 정의 및 관리
- 글로벌 예외 처리

### 🔧 [Utility Classes Guide](docs/util-guide.md)
- 날짜/시간 처리 유틸리티 (DateUtil)
- 문자열 처리 유틸리티 (StringUtil, 마스킹, 검증)
- 비밀번호 처리 유틸리티 (PasswordUtil, 암호화, 임시비밀번호)
- 유효성 검증 유틸리티 (ValidationUtil, 이메일/전화번호/사업자번호)
- JSON 처리 유틸리티 (JsonUtil, 직렬화/역직렬화)
- 파일 처리 유틸리티 (FileUtil, 업로드 검증, 파일명 처리)
- 컬렉션 유틸리티 (CollectionUtil, 분할/교집합/변환)

## 빠른 참조

### 새 프로젝트 시작시
1. [Spring Initializr](https://start.spring.io/)에서 기본 설정으로 프로젝트 생성
2. `docs/spring-config.md` 참조하여 환경별 설정 파일 생성
3. `docs/spring-patterns.md` 참조하여 BaseEntity/BaseTimeEntity 및 기본 구조 설정

### 새 기능 개발시
1. `docs/spring-patterns.md` 참조하여 Entity, DTO, Repository 설계
2. `docs/spring-examples.md` 참조하여 Controller, Service 구현
3. `docs/testing-guide.md` 참조하여 테스트 코드 작성

### API 문서화시
1. `docs/monitoring-api.md` 참조하여 OpenAPI 애노테이션 추가
2. Controller에 @Tag, @Operation 애노테이션 적용
3. DTO에 @Schema 애노테이션으로 상세 설명 추가

### 에러 처리시
1. `docs/monitoring-api.md`의 ErrorCode Enum 참조
2. BusinessException 계열 커스텀 예외 사용
3. GlobalExceptionHandler에서 통일된 에러 응답 처리

## Notes

- 모든 새로운 기능에는 테스트 코드 필수
- 코드 변경시 관련 문서 업데이트
- 성능에 영향을 주는 변경사항은 사전 논의
- 보안 관련 변경사항은 특히 신중하게 검토
- API 문서는 개발과 동시에 업데이트
- 에러 코드는 체계적으로 관리하고 문서화

# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.