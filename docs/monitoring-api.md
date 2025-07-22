# Monitoring and API Documentation Guide

이 문서는 Spring Boot 프로젝트의 모니터링, 로깅, API 문서화 및 에러 코드 관리에 대한 가이드를 제공합니다.

## 모니터링 및 로깅

### 로깅 전략

#### 기본 로깅 설정

```java
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class UserService {

    private final UserRepository userRepository;

    @Transactional
    public UserResponse createUser(UserCreateRequest request) {
        log.info("사용자 생성 요청: email={}", request.getEmail());

        try {
            validateDuplicateEmail(request.getEmail());

            User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .status(UserStatus.ACTIVE)
                .role(UserRole.USER)
                .build();

            User savedUser = userRepository.save(user);
            log.info("사용자 생성 완료: id={}, email={}", savedUser.getId(), savedUser.getEmail());

            return UserResponse.from(savedUser);
        } catch (Exception e) {
            log.error("사용자 생성 실패: email={}, error={}", request.getEmail(), e.getMessage());
            throw e;
        }
    }
}
```

#### 로깅 레벨 관리

**환경별 로깅 레벨**

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

#### 구조화된 로깅 (Logback JSON)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <springProfile name="prod">
        <appender name="JSON_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
            <file>/var/log/app/application.log</file>
            <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
                <fileNamePattern>/var/log/app/application.%d{yyyy-MM-dd}.gz</fileNamePattern>
                <maxHistory>30</maxHistory>
            </rollingPolicy>
            <encoder class="net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder">
                <providers>
                    <timestamp/>
                    <logLevel/>
                    <loggerName/>
                    <message/>
                    <mdc/>
                    <stackTrace/>
                </providers>
            </encoder>
        </appender>
        <root level="INFO">
            <appender-ref ref="JSON_FILE"/>
        </root>
    </springProfile>
</configuration>
```

### Health Check 설정

#### 상세한 Health Check 설정

```yaml
# application.yml
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

#### 커스텀 Health Indicator

```java
@Component
public class CustomHealthIndicator implements HealthIndicator {

    private final UserRepository userRepository;

    public CustomHealthIndicator(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Health health() {
        try {
            long userCount = userRepository.count();

            if (userCount >= 0) {
                return Health.up()
                    .withDetail("userCount", userCount)
                    .withDetail("status", "Database connection is healthy")
                    .build();
            } else {
                return Health.down()
                    .withDetail("status", "Unable to query user count")
                    .build();
            }
        } catch (Exception e) {
            return Health.down()
                .withDetail("status", "Database connection failed")
                .withDetail("error", e.getMessage())
                .build();
        }
    }
}
```

#### 애플리케이션 정보 설정

```java
@Component
public class AppInfoContributor implements InfoContributor {

    @Override
    public void contribute(Info.Builder builder) {
        builder.withDetail("app", Map.of(
            "name", "Spring Boot Project",
            "version", "1.0.0",
            "environment", getActiveProfile(),
            "buildTime", getBuildTime()
        ));
    }

    private String getActiveProfile() {
        return System.getProperty("spring.profiles.active", "unknown");
    }

    private String getBuildTime() {
        return LocalDateTime.now().toString();
    }
}
```

### 메트릭 수집

#### Micrometer 설정

```java
@Configuration
public class MetricsConfig {

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> metricsCommonTags() {
        return registry -> registry.config().commonTags(
            "application", "thetelos-project",
            "region", "kr-central-1"
        );
    }

    @Bean
    public TimedAspect timedAspect(MeterRegistry registry) {
        return new TimedAspect(registry);
    }
}
```

#### 커스텀 메트릭

```java
@Service
@RequiredArgsConstructor
public class UserMetricsService {

    private final MeterRegistry meterRegistry;
    private final Counter userCreationCounter;
    private final Timer userCreationTimer;

    public UserMetricsService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.userCreationCounter = Counter.builder("user.creation.count")
            .description("Number of users created")
            .register(meterRegistry);
        this.userCreationTimer = Timer.builder("user.creation.duration")
            .description("User creation duration")
            .register(meterRegistry);
    }

    @Timed(name = "user.service.operation", description = "User service operation time")
    public UserResponse createUser(UserCreateRequest request) {
        return Timer.Sample.start(meterRegistry)
            .stop(userCreationTimer.start())
            .recordCallable(() -> {
                userCreationCounter.increment();
                // 실제 사용자 생성 로직
                return createUserInternal(request);
            });
    }
}
```

#### Prometheus 연동

```yaml
management:
  endpoints:
    web:
      exposure:
        include: prometheus
  metrics:
    export:
      prometheus:
        enabled: true
```

### 분산 추적 (Zipkin/Jaeger)

```yaml
management:
  tracing:
    sampling:
      probability: 1.0
  zipkin:
    tracing:
      endpoint: http://zipkin:9411/api/v2/spans
```

```java
@Configuration
public class TracingConfig {

    @Bean
    public Sender sender() {
        return OkHttpSender.create("http://zipkin:9411/api/v2/spans");
    }

    @Bean
    public AsyncReporter<Span> spanReporter() {
        return AsyncReporter.create(sender());
    }
}
```

## API 문서화 전략

### SpringDoc OpenAPI 3 설정

#### OpenAPI 기본 설정

```java
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Thetelos Project API")
                .version("v1.0")
                .description("Spring Boot 3.x 기반 RESTful API 문서")
                .contact(new Contact()
                    .name("API Support")
                    .email("support@thetelos.net")
                    .url("https://thetelos.net"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth", new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("JWT 토큰을 입력하세요")))
            .servers(List.of(
                new Server().url("http://localhost:8080").description("Development Server"),
                new Server().url("https://api.thetelos.net").description("Production Server")
            ));
    }

    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
            .group("public")
            .pathsToMatch("/api/v1/**")
            .pathsToExclude("/api/v1/admin/**")
            .build();
    }

    @Bean
    public GroupedOpenApi adminApi() {
        return GroupedOpenApi.builder()
            .group("admin")
            .pathsToMatch("/api/v1/admin/**")
            .build();
    }
}
```

#### Controller 문서화

```java
@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "User Management", description = "사용자 관리 API")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    @GetMapping("/{id}")
    @Operation(
        summary = "사용자 조회",
        description = "ID로 특정 사용자 정보를 조회합니다.",
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "조회 성공",
                content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = CommonResponse.class),
                    examples = @ExampleObject(
                        name = "성공 예시",
                        value = """
                        {
                          "success": true,
                          "data": {
                            "id": 1,
                            "name": "홍길동",
                            "email": "hong@example.com",
                            "status": "ACTIVE"
                          },
                          "timestamp": "2024-01-01T12:00:00"
                        }
                        """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "404",
                description = "사용자를 찾을 수 없음",
                content = @Content(
                    schema = @Schema(implementation = CommonResponse.class),
                    examples = @ExampleObject(
                        name = "오류 예시",
                        value = """
                        {
                          "success": false,
                          "message": "사용자를 찾을 수 없습니다. ID: 999",
                          "errorCode": "ENTITY_NOT_FOUND",
                          "timestamp": "2024-01-01T12:00:00"
                        }
                        """
                    )
                )
            )
        }
    )
    public ResponseEntity<CommonResponse<UserResponse>> getUser(
            @Parameter(
                description = "사용자 ID",
                required = true,
                example = "1",
                schema = @Schema(type = "integer", minimum = "1")
            )
            @PathVariable @Positive Long id) {
        // 구현 코드
    }

    @PostMapping
    @Operation(
        summary = "사용자 생성",
        description = "새로운 사용자를 생성합니다."
    )
    public ResponseEntity<CommonResponse<UserResponse>> createUser(
            @RequestBody @Valid
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "사용자 생성 요청",
                required = true,
                content = @Content(
                    schema = @Schema(implementation = UserCreateRequest.class),
                    examples = @ExampleObject(
                        name = "사용자 생성 예시",
                        value = """
                        {
                          "name": "홍길동",
                          "email": "hong@example.com"
                        }
                        """
                    )
                )
            )
            UserCreateRequest request) {
        // 구현 코드
    }
}
```

#### DTO 문서화

```java
@Schema(description = "사용자 생성 요청")
public class UserCreateRequest {

    @Schema(
        description = "사용자 이름",
        example = "홍길동",
        requiredMode = Schema.RequiredMode.REQUIRED,
        minLength = 1,
        maxLength = 100
    )
    @NotBlank(message = "이름은 필수입니다")
    @Size(max = 100, message = "이름은 100자를 초과할 수 없습니다")
    private String name;

    @Schema(
        description = "이메일 주소",
        example = "hong@example.com",
        requiredMode = Schema.RequiredMode.REQUIRED,
        format = "email",
        maxLength = 255
    )
    @Email(message = "올바른 이메일 형식이 아닙니다")
    @NotBlank(message = "이메일은 필수입니다")
    @Size(max = 255, message = "이메일은 255자를 초과할 수 없습니다")
    private String email;
}

@Schema(description = "사용자 응답")
public class UserResponse {

    @Schema(description = "사용자 ID", example = "1")
    private Long id;

    @Schema(description = "사용자 이름", example = "홍길동")
    private String name;

    @Schema(description = "이메일 주소", example = "hong@example.com")
    private String email;

    @Schema(description = "사용자 상태", example = "ACTIVE")
    private UserStatus status;

    @Schema(description = "생성 시간", example = "2024-01-01T12:00:00")
    private LocalDateTime createdAt;
}
```

#### API 버전 관리 문서화

```java
@Configuration
public class OpenApiVersionConfig {

    @Bean
    public GroupedOpenApi v1Api() {
        return GroupedOpenApi.builder()
            .group("v1")
            .pathsToMatch("/api/v1/**")
            .addOpenApiCustomizer(openApi -> {
                openApi.info(new Info()
                    .title("API v1")
                    .version("1.0")
                    .description("첫 번째 버전 API"));
            })
            .build();
    }

    @Bean
    public GroupedOpenApi v2Api() {
        return GroupedOpenApi.builder()
            .group("v2")
            .pathsToMatch("/api/v2/**")
            .addOpenApiCustomizer(openApi -> {
                openApi.info(new Info()
                    .title("API v2")
                    .version("2.0")
                    .description("두 번째 버전 API (개선된 기능)"));
            })
            .build();
    }
}
```

## 에러 코드 정의

### 표준 에러 코드 체계

#### 에러 코드 Enum

```java
@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // 공통 에러 (1000번대)
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "COMMON_001", "잘못된 요청입니다."),
    VALIDATION_ERROR(HttpStatus.BAD_REQUEST, "COMMON_002", "입력값 검증에 실패했습니다."),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "COMMON_003", "서버 내부 오류가 발생했습니다."),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "COMMON_004", "지원하지 않는 HTTP 메서드입니다."),
    MEDIA_TYPE_NOT_SUPPORTED(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "COMMON_005", "지원하지 않는 미디어 타입입니다."),

    // 인증/인가 에러 (2000번대)
    AUTHENTICATION_REQUIRED(HttpStatus.UNAUTHORIZED, "AUTH_001", "인증이 필요합니다."),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "AUTH_002", "접근 권한이 없습니다."),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "AUTH_003", "유효하지 않은 토큰입니다."),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "AUTH_004", "만료된 토큰입니다."),
    REFRESH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "AUTH_005", "리프레시 토큰이 만료되었습니다."),

    // 사용자 관련 에러 (3000번대)
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "USER_001", "사용자를 찾을 수 없습니다."),
    DUPLICATE_EMAIL(HttpStatus.CONFLICT, "USER_002", "이미 사용중인 이메일입니다."),
    INVALID_PASSWORD(HttpStatus.BAD_REQUEST, "USER_003", "비밀번호가 일치하지 않습니다."),
    USER_ALREADY_DEACTIVATED(HttpStatus.BAD_REQUEST, "USER_004", "이미 비활성화된 사용자입니다."),
    USER_PERMISSION_DENIED(HttpStatus.FORBIDDEN, "USER_005", "사용자 권한이 부족합니다."),

    // 비즈니스 로직 에러 (4000번대)
    INSUFFICIENT_BALANCE(HttpStatus.BAD_REQUEST, "BUSINESS_001", "잔액이 부족합니다."),
    ORDER_ALREADY_PROCESSED(HttpStatus.CONFLICT, "BUSINESS_002", "이미 처리된 주문입니다."),
    INVALID_ORDER_STATUS(HttpStatus.BAD_REQUEST, "BUSINESS_003", "유효하지 않은 주문 상태입니다."),

    // 외부 API 에러 (5000번대)
    EXTERNAL_API_ERROR(HttpStatus.BAD_GATEWAY, "EXTERNAL_001", "외부 API 호출 중 오류가 발생했습니다."),
    PAYMENT_API_ERROR(HttpStatus.BAD_GATEWAY, "EXTERNAL_002", "결제 API 호출 실패"),

    // 리소스 관련 에러 (6000번대)
    FILE_UPLOAD_ERROR(HttpStatus.BAD_REQUEST, "RESOURCE_001", "파일 업로드 중 오류가 발생했습니다."),
    FILE_SIZE_EXCEEDED(HttpStatus.PAYLOAD_TOO_LARGE, "RESOURCE_002", "파일 크기가 제한을 초과했습니다."),
    INVALID_FILE_FORMAT(HttpStatus.BAD_REQUEST, "RESOURCE_003", "지원하지 않는 파일 형식입니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;

    public static ErrorCode fromCode(String code) {
        return Arrays.stream(values())
            .filter(errorCode -> errorCode.code.equals(code))
            .findFirst()
            .orElse(INTERNAL_SERVER_ERROR);
    }
}
```

#### 커스텀 예외 클래스

```java
@Getter
public class BusinessException extends RuntimeException {

    private final ErrorCode errorCode;
    private final Object[] args;

    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.args = new Object[0];
    }

    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.args = new Object[0];
    }

    public BusinessException(ErrorCode errorCode, Object... args) {
        super(String.format(errorCode.getMessage(), args));
        this.errorCode = errorCode;
        this.args = args;
    }

    public BusinessException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(), cause);
        this.errorCode = errorCode;
        this.args = new Object[0];
    }
}

@Getter
public class EntityNotFoundException extends BusinessException {
    public EntityNotFoundException(String entityName, Object id) {
        super(ErrorCode.USER_NOT_FOUND, entityName + "을(를) 찾을 수 없습니다. ID: " + id);
    }
}

@Getter
public class DuplicateException extends BusinessException {
    public DuplicateException(String message) {
        super(ErrorCode.DUPLICATE_EMAIL, message);
    }
}
```

### 글로벌 예외 처리

#### 통합 Exception Handler

```java
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<CommonResponse<Void>> handleBusinessException(BusinessException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        log.warn("Business exception: [{}] {}", errorCode.getCode(), ex.getMessage());

        return ResponseEntity.status(errorCode.getHttpStatus())
            .body(CommonResponse.error(ex.getMessage(), errorCode.getCode()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<CommonResponse<Map<String, String>>> handleValidation(
            MethodArgumentNotValidException ex) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> 
            errors.put(error.getField(), error.getDefaultMessage())
        );

        String message = ex.getBindingResult().getFieldErrors().stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .collect(Collectors.joining(", "));

        log.warn("Validation error: {}", message);
        
        return ResponseEntity.status(ErrorCode.VALIDATION_ERROR.getHttpStatus())
            .body(CommonResponse.error(message, ErrorCode.VALIDATION_ERROR.getCode(), errors));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<CommonResponse<Void>> handleMethodNotAllowed(
            HttpRequestMethodNotSupportedException ex) {
        
        String message = "지원하지 않는 HTTP 메서드입니다: " + ex.getMethod();
        log.warn("Method not allowed: {}", message);
        
        return ResponseEntity.status(ErrorCode.METHOD_NOT_ALLOWED.getHttpStatus())
            .body(CommonResponse.error(message, ErrorCode.METHOD_NOT_ALLOWED.getCode()));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<CommonResponse<Void>> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex) {
        
        String message = "지원하지 않는 미디어 타입입니다: " + ex.getContentType();
        log.warn("Media type not supported: {}", message);
        
        return ResponseEntity.status(ErrorCode.MEDIA_TYPE_NOT_SUPPORTED.getHttpStatus())
            .body(CommonResponse.error(message, ErrorCode.MEDIA_TYPE_NOT_SUPPORTED.getCode()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<CommonResponse<Void>> handleAccessDenied(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        
        return ResponseEntity.status(ErrorCode.ACCESS_DENIED.getHttpStatus())
            .body(CommonResponse.error(ErrorCode.ACCESS_DENIED.getMessage(), ErrorCode.ACCESS_DENIED.getCode()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<CommonResponse<Void>> handleGeneral(Exception ex, HttpServletRequest request) {
        String requestId = UUID.randomUUID().toString();
        log.error("Unexpected error [{}]: {} {}", requestId, request.getMethod(), request.getRequestURI(), ex);
        
        return ResponseEntity.status(ErrorCode.INTERNAL_SERVER_ERROR.getHttpStatus())
            .body(CommonResponse.error(
                "서버 내부 오류가 발생했습니다. 요청 ID: " + requestId,
                ErrorCode.INTERNAL_SERVER_ERROR.getCode()
            ));
    }
}
```

### 에러 응답 표준화

#### CommonResponse 개선

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Schema(description = "API 응답 표준 형식")
public class CommonResponse<T> {

    @Schema(description = "성공 여부", example = "true")
    private boolean success;

    @Schema(description = "응답 데이터")
    private T data;

    @Schema(description = "메시지", example = "요청이 성공적으로 처리되었습니다.")
    private String message;

    @Schema(description = "에러 코드", example = "USER_001")
    private String errorCode;

    @Schema(description = "응답 시간", example = "2024-01-01T12:00:00")
    private LocalDateTime timestamp;

    @Schema(description = "요청 경로", example = "/api/v1/users/1")
    private String path;

    public static <T> CommonResponse<T> success(T data) {
        return CommonResponse.<T>builder()
            .success(true)
            .data(data)
            .message("요청이 성공적으로 처리되었습니다.")
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static <T> CommonResponse<T> success(T data, String message) {
        return CommonResponse.<T>builder()
            .success(true)
            .data(data)
            .message(message)
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static CommonResponse<Void> success() {
        return CommonResponse.<Void>builder()
            .success(true)
            .message("요청이 성공적으로 처리되었습니다.")
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static <T> CommonResponse<T> error(String message, String errorCode) {
        return CommonResponse.<T>builder()
            .success(false)
            .message(message)
            .errorCode(errorCode)
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static <T> CommonResponse<T> error(String message, String errorCode, T data) {
        return CommonResponse.<T>builder()
            .success(false)
            .message(message)
            .errorCode(errorCode)
            .data(data)
            .timestamp(LocalDateTime.now())
            .build();
    }
}
```

### 에러 코드 문서화

#### 에러 코드 문서 자동 생성

```java
@RestController
@RequestMapping("/api/docs")
@Tag(name = "Documentation", description = "API 문서화 관련 엔드포인트")
public class DocumentationController {

    @GetMapping("/error-codes")
    @Operation(summary = "에러 코드 목록", description = "시스템에서 사용하는 모든 에러 코드를 조회합니다.")
    public ResponseEntity<CommonResponse<List<ErrorCodeResponse>>> getErrorCodes() {
        List<ErrorCodeResponse> errorCodes = Arrays.stream(ErrorCode.values())
            .map(ErrorCodeResponse::from)
            .collect(Collectors.toList());

        return ResponseEntity.ok(CommonResponse.success(errorCodes));
    }

}

// ErrorCodeResponse DTO - 별도 클래스로 분리
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Schema(description = "에러 코드 응답")
public class ErrorCodeResponse {
    
    @Schema(description = "에러 코드", example = "USER_001")
    private String code;
    
    @Schema(description = "HTTP 상태 코드", example = "404")
    private int httpStatus;
    
    @Schema(description = "에러 메시지", example = "사용자를 찾을 수 없습니다.")
    private String message;
    
    @Schema(description = "카테고리", example = "USER")
    private String category;

    public static ErrorCodeResponse from(ErrorCode errorCode) {
        return ErrorCodeResponse.builder()
            .code(errorCode.getCode())
            .httpStatus(errorCode.getHttpStatus().value())
            .message(errorCode.getMessage())
            .category(errorCode.getCode().split("_")[0])
            .build();
    }
}
```

### 모니터링 알림 설정

#### 로그 기반 알림

```java
@Component
@Slf4j
public class AlertingService {

    private final MeterRegistry meterRegistry;
    private final Counter errorCounter;

    public AlertingService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.errorCounter = Counter.builder("application.errors")
            .description("Application error count")
            .register(meterRegistry);
    }

    @EventListener
    public void handleException(ApplicationEvent event) {
        if (event instanceof ExceptionEvent) {
            ExceptionEvent exceptionEvent = (ExceptionEvent) event;
            errorCounter.increment(
                Tags.of(
                    "error.type", exceptionEvent.getException().getClass().getSimpleName(),
                    "error.code", getErrorCode(exceptionEvent.getException())
                )
            );

            // 심각한 오류인 경우 즉시 알림
            if (isCriticalError(exceptionEvent.getException())) {
                sendCriticalAlert(exceptionEvent);
            }
        }
    }

    private boolean isCriticalError(Throwable exception) {
        return exception instanceof DataIntegrityViolationException
            || exception instanceof SQLException
            || exception.getMessage().contains("OutOfMemoryError");
    }

    private void sendCriticalAlert(ExceptionEvent event) {
        log.error("CRITICAL ERROR DETECTED", event.getException());
        // 실제 알림 서비스 연동 (Slack, Email 등)
    }
}
```

이러한 모니터링, API 문서화, 에러 관리 체계를 통해 운영 환경에서 안정적이고 관리 가능한 Spring Boot 애플리케이션을 구축할 수 있습니다.