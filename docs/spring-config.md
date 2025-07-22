# Spring Boot Configuration Guide

이 문서는 Spring Boot 프로젝트의 환경별 설정 관리 및 성능 최적화에 대한 가이드를 제공합니다.

## 환경별 설정 관리

### @ConfigurationProperties 활용

**설정 클래스 정의**

```java
@ConfigurationProperties(prefix = "app")
@Component
@Validated
@Getter
@Setter
public class AppProperties {

    private JwtProperties jwt = new JwtProperties();
    private CorsProperties cors = new CorsProperties();
    private UploadProperties upload = new UploadProperties();
}

// JWT 관련 설정 - 별도 클래스로 분리
@ConfigurationProperties(prefix = "app.jwt")
@Component
@Validated
@Getter
@Setter
public class JwtProperties {
    @NotBlank
    private String secret;

    @Positive
    private Long accessTokenExpiration = 3600L;  // 1시간

    @Positive
    private Long refreshTokenExpiration = 604800L;  // 7일
}

// CORS 관련 설정 - 별도 클래스로 분리
@ConfigurationProperties(prefix = "app.cors")
@Component
@Validated
@Getter
@Setter
public class CorsProperties {
    private List<String> allowedOrigins = List.of("http://localhost:3000");
    private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");
    private List<String> allowedHeaders = List.of("*");
    private boolean allowCredentials = true;
}

// 업로드 관련 설정 - 별도 클래스로 분리
@ConfigurationProperties(prefix = "app.upload")
@Component
@Validated
@Getter
@Setter
public class UploadProperties {
    @NotBlank
    private String path = "/tmp/uploads";

    @Positive
    private Long maxFileSize = 10485760L;  // 10MB
}
```

### 환경별 설정 파일

#### application.yml (공통 설정)

```yaml
spring:
  profiles:
    active: dev

  application:
    name: thetelos-project

  jpa:
    open-in-view: false
    properties:
      hibernate:
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true

app:
  cors:
    allowed-origins:
      - http://localhost:3000
      - http://localhost:8080
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
      - PATCH
      - OPTIONS

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
  health:
    redis:
      enabled: true
    db:
      enabled: true

logging:
  level:
    root: INFO
    net.thetelos: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
```

#### application-dev.yml (개발 환경)

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/thetelos_dev
    username: ${DB_USERNAME:dev_user}
    password: ${DB_PASSWORD:dev_password}
    hikari:
      maximum-pool-size: 10
      minimum-idle: 2

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        format_sql: true

  redis:
    host: localhost
    port: 6379
    password: ${REDIS_PASSWORD:}

  cache:
    type: redis

app:
  jwt:
    secret: ${JWT_SECRET:dev-secret-key-must-be-changed-in-production}
    access-token-expiration: 3600 # 1시간
    refresh-token-expiration: 604800 # 7일
  upload:
    path: ${UPLOAD_PATH:/tmp/dev-uploads}
    max-file-size: 10485760 # 10MB

logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    net.thetelos: DEBUG
```

#### application-prod.yml (운영 환경)

```yaml
spring:
  datasource:
    url: ${DB_URL}
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000

  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false

  redis:
    host: ${REDIS_HOST}
    port: ${REDIS_PORT:6379}
    password: ${REDIS_PASSWORD}
    ssl: true

  cache:
    type: redis

app:
  jwt:
    secret: ${JWT_SECRET}
    access-token-expiration: 1800 # 30분 (보안 강화)
    refresh-token-expiration: 604800 # 7일
  cors:
    allowed-origins:
      - ${FRONTEND_URL}
      - ${ADMIN_URL}
  upload:
    path: ${UPLOAD_PATH:/var/app/uploads}
    max-file-size: 5242880 # 5MB (운영환경에서는 더 제한적)

logging:
  level:
    root: WARN
    net.thetelos: INFO
  file:
    name: ${LOG_PATH:/var/log/app}/application.log
```

#### application-test.yml (테스트 환경)

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE
    username: sa
    password:
    driver-class-name: org.h2.Driver

  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true

  redis:
    host: localhost
    port: 6370 # 테스트용 포트

app:
  jwt:
    secret: test-secret-key
    access-token-expiration: 3600
    refresh-token-expiration: 604800
  upload:
    path: /tmp/test-uploads
    max-file-size: 1048576 # 1MB (테스트용)

logging:
  level:
    root: INFO
    net.thetelos: DEBUG
```

### 민감정보 환경변수 처리

#### 환경변수 설정 예시

```bash
# .env 파일 (개발용, .gitignore에 추가)
DB_URL=jdbc:postgresql://localhost:5432/thetelos_dev
DB_USERNAME=dev_user
DB_PASSWORD=dev_password
JWT_SECRET=your-secret-key
REDIS_PASSWORD=redis-password
```

#### Docker 환경변수

```dockerfile
ENV DB_URL=jdbc:postgresql://db:5432/thetelos
ENV DB_USERNAME=app_user
ENV JWT_SECRET=production-secret-key
```

#### Kubernetes ConfigMap/Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
data:
  jwt-secret: <base64-encoded-secret>
  db-password: <base64-encoded-password>
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DB_URL: "jdbc:postgresql://postgres:5432/thetelos"
  REDIS_HOST: "redis"
```

## 성능 최적화

### JPA 성능 최적화

#### 배치 처리 설정

```yaml
spring:
  jpa:
    properties:
      hibernate:
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true
        batch_versioned_data: true
```

#### 페치 조인으로 N+1 문제 해결

```java
// N+1 문제 발생 코드
List<User> users = userRepository.findAll();
users.forEach(user -> user.getOrders().size()); // 각 사용자마다 추가 쿼리

// 해결: 페치 조인 사용
@Query("SELECT u FROM User u JOIN FETCH u.orders")
List<User> findAllWithOrders();

// 또는 EntityGraph 사용
@EntityGraph(attributePaths = {"orders"})
List<User> findAll();
```

#### 페이징과 정렬 최적화

```java
// 커버링 인덱스 활용
Pageable pageable = PageRequest.of(0, 10, Sort.by("createdAt").descending());
Page<User> users = userRepository.findAll(pageable);
```

### Connection Pool 최적화 (HikariCP)

```yaml
spring:
  datasource:
    hikari:
      # 커넥션 풀 크기 설정
      maximum-pool-size: 20
      minimum-idle: 5

      # 타임아웃 설정
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000

      # 연결 검증
      connection-test-query: SELECT 1
      validation-timeout: 5000

      # 성능 최적화
      auto-commit: false
      read-only: false
```

### Redis 캐싱 전략

#### 캐시 설정

```yaml
spring:
  cache:
    type: redis
  redis:
    host: localhost
    port: 6379
    timeout: 2000ms
    lettuce:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 0
```

#### 캐시 사용 패턴

```java
@Service
@Transactional(readOnly = true)
public class UserService {

    // 조회 캐싱
    @Cacheable(value = "users", key = "#id")
    public UserResponse findById(Long id) {
        return userRepository.findById(id)
            .map(UserResponse::from)
            .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다."));
    }

    // 수정시 캐시 삭제
    @CacheEvict(value = "users", key = "#id")
    @Transactional
    public UserResponse updateUser(Long id, UserUpdateRequest request) {
        // 업데이트 로직
    }

    // 전체 캐시 삭제
    @CacheEvict(value = "users", allEntries = true)
    @Transactional
    public void deleteUser(Long id) {
        // 삭제 로직
    }
}
```

### QueryDSL 성능 최적화

#### 프로젝션 활용한 필요 컬럼만 조회

```java
@Repository
@RequiredArgsConstructor
public class UserQueryRepository {

    private final JPAQueryFactory queryFactory;

    // DTO 프로젝션으로 성능 최적화
    public List<UserListResponse> findUserList() {
        return queryFactory
            .select(Projections.constructor(UserListResponse.class,
                user.id,
                user.name,
                user.email,
                user.status))
            .from(user)
            .orderBy(user.createdAt.desc())
            .fetch();
    }

    // 서브쿼리 최적화
    public List<User> findActiveUsersWithRecentOrders() {
        return queryFactory
            .selectFrom(user)
            .where(user.status.eq(UserStatus.ACTIVE)
                .and(JPAExpressions
                    .select(order.count())
                    .from(order)
                    .where(order.user.eq(user)
                        .and(order.createdAt.gt(LocalDateTime.now().minusDays(30))))
                    .gt(0L)))
            .fetch();
    }
}
```

### 데이터베이스 인덱스 전략

#### 인덱스 생성 예시

```java
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_users_email", columnList = "email"),
    @Index(name = "idx_users_status_created", columnList = "status, created_at"),
    @Index(name = "idx_users_name", columnList = "name")
})
public class User extends BaseEntity {
    // 엔티티 정의
}
```

#### 복합 인덱스 활용

```sql
-- 자주 함께 사용되는 컬럼들의 복합 인덱스
CREATE INDEX idx_users_status_created_at ON users(status, created_at);

-- 커버링 인덱스 (조회하는 모든 컬럼을 인덱스에 포함)
CREATE INDEX idx_users_covering ON users(status, created_at) INCLUDE (id, name, email);
```

## 보안 설정

### 보안 고려사항

- **Password 암호화**: PasswordUtil 사용하여 안전한 패스워드 저장 (내부적으로 BCryptPasswordEncoder 활용)
- **JWT 토큰 관리**: Access Token(짧은 만료시간) + Refresh Token(Redis 저장) 조합
- **CORS 설정**: 허용할 Origin, Method, Header 명시적 설정
- **CSRF 보호**: RESTful API는 CSRF 비활성화, 상태 유지 애플리케이션은 활성화
- **Security Filter Chain**: SecurityFilterChain Bean 방식으로 최신 설정
- **Authentication Entry Point**: 인증 실패시 커스텀 응답 처리
- **Access Denied Handler**: 권한 부족시 커스텀 응답 처리
- **Authentication Success/Failure Handler**: 로그인 성공/실패시 커스텀 처리
- **Method Security**: @PreAuthorize, @PostAuthorize를 통한 메서드 레벨 보안
- **SQL Injection 방지**: JPA, QueryDSL 사용으로 자동 방지
- **XSS 방지**: 입력값 검증 및 출력시 이스케이프 처리
- **민감정보 로깅 금지**: 패스워드, 토큰 등 민감정보 로그 출력 방지

### CORS 설정 예시

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(List.of("http://localhost:3000", "https://*.example.com"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", configuration);
    return source;
}
```

## 프로파일 관리

### Environment Profiles

- `dev`: 개발 환경
- `stg`: 스테이징 환경  
- `prod`: 운영 환경
- `test`: 테스트 환경 (H2 DB 사용)

### 프로파일별 활성화

```bash
# 개발 환경
java -jar app.jar --spring.profiles.active=dev

# 운영 환경
java -jar app.jar --spring.profiles.active=prod

# 다중 프로파일
java -jar app.jar --spring.profiles.active=prod,monitoring
```

### 환경별 빌드 설정

#### Gradle 설정

```gradle
configurations {
    developmentOnly
    runtimeClasspath {
        extendsFrom developmentOnly
    }
}

dependencies {
    // 개발 환경에서만 포함
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
    
    // 운영 환경에서만 포함
    implementation 'org.springframework.boot:spring-boot-starter-actuator'
}

// 프로파일별 빌드
task buildDev(type: Jar) {
    archiveClassifier = 'dev'
    from sourceSets.main.output
}

task buildProd(type: Jar) {
    archiveClassifier = 'prod'
    from sourceSets.main.output
    exclude 'application-dev.yml'
}
```

### Docker 환경 설정

#### Dockerfile

```dockerfile
FROM openjdk:17-jre-slim

ARG PROFILE=prod
ENV SPRING_PROFILES_ACTIVE=${PROFILE}

COPY build/libs/app.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app.jar"]
```

#### docker-compose.yml

```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - DB_URL=jdbc:postgresql://db:5432/thetelos
      - DB_USERNAME=app_user
      - DB_PASSWORD=app_password
    ports:
      - "8080:8080"
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=thetelos
      - POSTGRES_USER=app_user
      - POSTGRES_PASSWORD=app_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

## 로깅 설정

### 환경별 로깅 레벨

```yaml
# 개발 환경
logging:
  level:
    root: INFO
    net.thetelos: DEBUG
    org.hibernate.SQL: DEBUG
    org.springframework.web: DEBUG

# 운영 환경
logging:
  level:
    root: WARN
    net.thetelos: INFO
    org.hibernate.SQL: WARN
  file:
    name: /var/log/app/application.log
    max-size: 100MB
    max-history: 30
```

### Logback 설정 (logback-spring.xml)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <springProfile name="dev">
        <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
            <encoder>
                <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
            </encoder>
        </appender>
        <root level="INFO">
            <appender-ref ref="CONSOLE"/>
        </root>
    </springProfile>

    <springProfile name="prod">
        <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
            <file>/var/log/app/application.log</file>
            <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
                <fileNamePattern>/var/log/app/application.%d{yyyy-MM-dd}.gz</fileNamePattern>
                <maxHistory>30</maxHistory>
            </rollingPolicy>
            <encoder>
                <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
            </encoder>
        </appender>
        <root level="WARN">
            <appender-ref ref="FILE"/>
        </root>
    </springProfile>
</configuration>
```

## 모니터링 설정

### Actuator 설정

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
      base-path: /actuator
  endpoint:
    health:
      show-details: always
      show-components: always
  health:
    redis:
      enabled: true
    db:
      enabled: true
    diskspace:
      enabled: true
      threshold: 10737418240 # 10GB
  info:
    env:
      enabled: true
    git:
      mode: full
```

### Micrometer 메트릭 설정

```java
@Configuration
public class MetricsConfig {

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> metricsCommonTags() {
        return registry -> registry.config().commonTags("application", "thetelos-project");
    }

    @Bean
    public TimedAspect timedAspect(MeterRegistry registry) {
        return new TimedAspect(registry);
    }
}
```

이러한 설정들을 통해 환경별로 최적화된 Spring Boot 애플리케이션을 구성할 수 있습니다.