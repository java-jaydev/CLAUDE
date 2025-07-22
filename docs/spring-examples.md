# Spring Boot Code Examples

이 문서는 Spring Boot 프로젝트에서 사용하는 실제 코드 예시들을 제공합니다.

## Controller 예시

### REST Controller 구현

```java
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Validated
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping("/{id}")
    public ResponseEntity<CommonResponse<UserResponse>> getUser(
            @PathVariable @Positive Long id) {

        UserResponse user = userService.findById(id);
        return ResponseEntity.ok(CommonResponse.success(user));
    }

    @PostMapping
    public ResponseEntity<CommonResponse<UserResponse>> createUser(
            @RequestBody @Valid UserCreateRequest request) {

        UserResponse user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(CommonResponse.success(user));
    }

    @PutMapping("/{id}")
    public ResponseEntity<CommonResponse<UserResponse>> updateUser(
            @PathVariable @Positive Long id,
            @RequestBody @Valid UserUpdateRequest request) {

        UserResponse user = userService.updateUser(id, request);
        return ResponseEntity.ok(CommonResponse.success(user));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<CommonResponse<Void>> deleteUser(
            @PathVariable @Positive Long id) {

        userService.deleteUser(id);
        return ResponseEntity.ok(CommonResponse.success());
    }
}
```

### 페이징 응답 통합

```java
@GetMapping
public ResponseEntity<CommonResponse<PageResponse<UserResponse>>> getUsers(Pageable pageable) {
    Page<User> users = userService.findUsers(pageable);
    PageResponse<UserResponse> pageResponse = PageResponse.from(users.map(UserResponse::from));
    return ResponseEntity.ok(CommonResponse.success(pageResponse));
}
```

## Service 예시

### 완전한 Service 구현

```java
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final UserQueryRepository userQueryRepository;

    public UserResponse findById(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다. ID: " + id));

        return UserResponse.from(user);
    }

    public Page<UserResponse> findUsers(UserSearchCondition condition, Pageable pageable) {
        Page<User> users = userQueryRepository.findByCondition(condition, pageable);
        return users.map(UserResponse::from);
    }

    @Transactional
    public UserResponse createUser(UserCreateRequest request) {
        validateDuplicateEmail(request.getEmail());

        User user = User.builder()
            .name(request.getName())
            .email(request.getEmail())
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();

        User savedUser = userRepository.save(user);
        log.info("새로운 사용자가 생성되었습니다. ID: {}, Email: {}", savedUser.getId(), savedUser.getEmail());

        return UserResponse.from(savedUser);
    }

    @Transactional
    public UserResponse updateUser(Long id, UserUpdateRequest request) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다. ID: " + id));

        if (!user.getEmail().equals(request.getEmail())) {
            validateDuplicateEmail(request.getEmail());
        }

        user.updateUserInfo(request.getName(), request.getEmail());
        return UserResponse.from(user);
    }

    @Transactional
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다. ID: " + id));

        userRepository.delete(user);
        log.info("사용자가 삭제되었습니다. ID: {}", id);
    }

    private void validateDuplicateEmail(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateException("이미 사용중인 이메일입니다: " + email);
        }
    }
}
```

## Entity 예시

### BaseEntity 구현

#### 1. BaseTimeEntity (시간 컬럼만)

시간 추적만 필요한 엔티티용 - 감사자 정보가 불필요한 경우 사용

```java
@MappedSuperclass
@Getter
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Comment("기본 키")
    private Long id;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    @Comment("생성 시간")
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    @Comment("수정 시간")
    private LocalDateTime updatedAt;
}
```

#### 2. BaseEntity (시간 + 감사자 컬럼)

완전한 감사 추적이 필요한 엔티티용 - 생성자/수정자 정보가 필요한 경우 사용

```java
@MappedSuperclass
@Getter
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Comment("기본 키")
    private Long id;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    @Comment("생성 시간")
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    @Comment("수정 시간")
    private LocalDateTime updatedAt;

    @CreatedBy
    @Column(name = "created_by", length = 100, updatable = false)
    @Comment("생성자")
    private String createdBy;

    @LastModifiedBy
    @Column(name = "updated_by", length = 100)
    @Comment("수정자")
    private String updatedBy;
}
```

#### 사용 가이드라인

**BaseTimeEntity 사용 권장 케이스:**
- 시스템 코드, 카테고리 등 마스터 데이터
- 로그성 데이터 (접근 로그, 시스템 로그 등)
- 감사자 정보가 불필요한 단순 엔티티

**BaseEntity 사용 권장 케이스:**
- 사용자 데이터 (회원, 게시글, 주문 등)
- 비즈니스 중요 데이터
- 감사 추적이 필요한 모든 엔티티

### 도메인 Entity 구현

#### BaseEntity 상속 (감사 추적 필요)

```java
@Entity
@Table(name = "users", comment = "사용자 정보")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class User extends BaseEntity {

    @Column(name = "name", nullable = false, length = 100)
    @Comment("사용자명")
    private String name;

    @Column(name = "email", nullable = false, unique = true, length = 255)
    @Comment("이메일 주소")
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Comment("사용자 상태")
    private UserStatus status;

    @Convert(converter = UserRoleConverter.class)
    @Column(name = "role", nullable = false, length = 20)
    @Comment("사용자 권한")
    private UserRole role;

    // 비즈니스 메서드
    public void updateUserInfo(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public boolean isActive() {
        return this.status == UserStatus.ACTIVE;
    }
}
```

#### BaseTimeEntity 상속 (시간 추적만)

```java
@Entity
@Table(name = "categories", comment = "카테고리 정보")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class Category extends BaseTimeEntity {

    @Column(name = "name", nullable = false, length = 100)
    @Comment("카테고리명")
    private String name;

    @Column(name = "code", nullable = false, unique = true, length = 50)
    @Comment("카테고리 코드")
    private String code;

    @Column(name = "parent_id")
    @Comment("상위 카테고리 ID")
    private Long parentId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Comment("카테고리 상태")
    private CategoryStatus status;

    @Column(name = "sort_order", nullable = false)
    @Comment("정렬 순서")
    private Integer sortOrder;
}
```

#### 로그 Entity (BaseTimeEntity 활용)

```java
@Entity
@Table(name = "access_logs", comment = "접근 로그")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class AccessLog extends BaseTimeEntity {

    @Column(name = "user_id")
    @Comment("사용자 ID")
    private Long userId;

    @Column(name = "ip_address", length = 45)
    @Comment("IP 주소")
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    @Comment("User Agent")
    private String userAgent;

    @Column(name = "request_uri", length = 500)
    @Comment("요청 URI")
    private String requestUri;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_type", nullable = false, length = 50)
    @Comment("액션 타입")
    private ActionType actionType;
}
```

## Enum 예시

### 상태 관리 Enum

```java
@Getter
@RequiredArgsConstructor
public enum UserStatus {
    ACTIVE("활성"),
    INACTIVE("비활성"),
    SUSPENDED("정지");

    private final String description;
}

@Getter
@RequiredArgsConstructor
public enum UserRole {
    ADMIN("ROLE_ADMIN", "관리자"),
    USER("ROLE_USER", "일반사용자"),
    GUEST("ROLE_GUEST", "게스트");

    private final String authority;
    private final String description;
}
```

## Converter 예시

### Enum Converter 구현

```java
@Converter
public class UserRoleConverter implements AttributeConverter<UserRole, String> {

    @Override
    public String convertToDatabaseColumn(UserRole attribute) {
        return attribute != null ? attribute.getAuthority() : null;
    }

    @Override
    public UserRole convertToEntityAttribute(String dbData) {
        return Arrays.stream(UserRole.values())
            .filter(role -> role.getAuthority().equals(dbData))
            .findFirst()
            .orElse(null);
    }
}
```

## QueryDSL Repository 구현체 예시

### 동적 쿼리 구현

```java
@Repository
@RequiredArgsConstructor
public class UserQueryRepository {

    private final JPAQueryFactory queryFactory;

    public Page<User> findByCondition(UserSearchCondition condition, Pageable pageable) {
        List<User> content = queryFactory
            .selectFrom(user)
            .where(
                nameContains(condition.getName()),
                emailContains(condition.getEmail()),
                statusEq(condition.getStatus())
            )
            .offset(pageable.getOffset())
            .limit(pageable.getPageSize())
            .orderBy(user.createdAt.desc())
            .fetch();

        JPAQuery<Long> countQuery = queryFactory
            .select(user.count())
            .from(user)
            .where(
                nameContains(condition.getName()),
                emailContains(condition.getEmail()),
                statusEq(condition.getStatus())
            );

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchOne);
    }

    private BooleanExpression nameContains(String name) {
        return StringUtils.hasText(name) ? user.name.contains(name) : null;
    }

    private BooleanExpression emailContains(String email) {
        return StringUtils.hasText(email) ? user.email.contains(email) : null;
    }

    private BooleanExpression statusEq(UserStatus status) {
        return status != null ? user.status.eq(status) : null;
    }
}
```

## CommonResponse 예시

### API 응답 표준화

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class CommonResponse<T> {

    private boolean success;
    private T data;
    private String message;
    private String errorCode;
    private LocalDateTime timestamp;

    public static <T> CommonResponse<T> success(T data) {
        return CommonResponse.<T>builder()
            .success(true)
            .data(data)
            .timestamp(LocalDateTime.now())
            .build();
    }

    public static CommonResponse<Void> success() {
        return CommonResponse.<Void>builder()
            .success(true)
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
}
```

## HTTP 상태 코드 예시

### 성공 응답 (2xx)

```java
// 200 OK - 조회 성공
@GetMapping("/{id}")
public ResponseEntity<CommonResponse<UserResponse>> getUser(@PathVariable Long id) {
    UserResponse user = userService.findById(id);
    return ResponseEntity.ok(CommonResponse.success(user));
}

// 201 Created - 리소스 생성 성공
@PostMapping
public ResponseEntity<CommonResponse<UserResponse>> createUser(@RequestBody @Valid UserCreateRequest request) {
    UserResponse user = userService.createUser(request);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(CommonResponse.success(user));
}

// 204 No Content - 삭제 성공 (응답 바디 없음)
@DeleteMapping("/{id}")
public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
    userService.deleteUser(id);
    return ResponseEntity.noContent().build();
}
```

### 클라이언트 오류 (4xx)

```java
// 400 Bad Request - 잘못된 요청
@ExceptionHandler(MethodArgumentNotValidException.class)
public ResponseEntity<CommonResponse<Void>> handleValidation(MethodArgumentNotValidException ex) {
    String message = ex.getBindingResult().getFieldErrors().stream()
        .map(error -> error.getField() + ": " + error.getDefaultMessage())
        .collect(Collectors.joining(", "));

    return ResponseEntity.badRequest()
        .body(CommonResponse.error(message, "VALIDATION_ERROR"));
}

// 401 Unauthorized - 인증 필요
@ExceptionHandler(AuthenticationException.class)
public ResponseEntity<CommonResponse<Void>> handleAuthentication(AuthenticationException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(CommonResponse.error("인증이 필요합니다.", "AUTHENTICATION_REQUIRED"));
}

// 403 Forbidden - 권한 부족
@ExceptionHandler(AccessDeniedException.class)
public ResponseEntity<CommonResponse<Void>> handleAccessDenied(AccessDeniedException ex) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(CommonResponse.error("접근 권한이 없습니다.", "ACCESS_DENIED"));
}

// 404 Not Found - 리소스 없음
@ExceptionHandler(EntityNotFoundException.class)
public ResponseEntity<CommonResponse<Void>> handleNotFound(EntityNotFoundException ex) {
    return ResponseEntity.status(HttpStatus.NOT_FOUND)
        .body(CommonResponse.error(ex.getMessage(), "ENTITY_NOT_FOUND"));
}

// 409 Conflict - 리소스 충돌
@ExceptionHandler(DuplicateException.class)
public ResponseEntity<CommonResponse<Void>> handleConflict(DuplicateException ex) {
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(CommonResponse.error(ex.getMessage(), "DUPLICATE_RESOURCE"));
}

// 422 Unprocessable Entity - 비즈니스 로직 오류
@ExceptionHandler(BusinessException.class)
public ResponseEntity<CommonResponse<Void>> handleBusinessLogic(BusinessException ex) {
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
        .body(CommonResponse.error(ex.getMessage(), ex.getErrorCode().getCode()));
}
```

### 서버 오류 (5xx)

```java
// 500 Internal Server Error - 서버 내부 오류
@ExceptionHandler(Exception.class)
public ResponseEntity<CommonResponse<Void>> handleGeneral(Exception ex) {
    log.error("Unexpected error", ex);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(CommonResponse.error("서버 내부 오류가 발생했습니다.", "INTERNAL_SERVER_ERROR"));
}

// 503 Service Unavailable - 서비스 일시 중단
@ExceptionHandler(ServiceUnavailableException.class)
public ResponseEntity<CommonResponse<Void>> handleServiceUnavailable(ServiceUnavailableException ex) {
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .body(CommonResponse.error("서비스가 일시적으로 사용할 수 없습니다.", "SERVICE_UNAVAILABLE"));
}
```

## API 버전 관리

### URL 경로 방식 (권장)

```java
// v1 API
@RestController
@RequestMapping("/api/v1/users")
public class UserV1Controller {
    // v1 구현
}

// v2 API (하위 호환성 유지)
@RestController
@RequestMapping("/api/v2/users")
public class UserV2Controller {
    // v2 구현 (개선된 기능)
}
```

## RESTful API 설계 원칙

### 리소스 중심 URL 설계

```java
// 올바른 예시
GET    /api/v1/users           // 사용자 목록 조회
GET    /api/v1/users/{id}      // 특정 사용자 조회
POST   /api/v1/users           // 사용자 생성
PUT    /api/v1/users/{id}      // 사용자 전체 수정
PATCH  /api/v1/users/{id}      // 사용자 부분 수정
DELETE /api/v1/users/{id}      // 사용자 삭제

// 중첩 리소스
GET    /api/v1/users/{id}/orders        // 특정 사용자의 주문 목록
POST   /api/v1/users/{id}/orders        // 특정 사용자의 주문 생성
GET    /api/v1/users/{id}/orders/{orderId}  // 특정 사용자의 특정 주문 조회

// 잘못된 예시 (동사 사용)
POST   /api/v1/createUser      // ❌
GET    /api/v1/getUserById     // ❌
POST   /api/v1/users/search    // ❌ (GET으로 쿼리 파라미터 사용)
```

## 글로벌 예외 처리 예시

### Exception Handler 구현

```java
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<CommonResponse<Void>> handleEntityNotFound(EntityNotFoundException ex) {
        log.warn("EntityNotFoundException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(CommonResponse.error(ex.getMessage(), "ENTITY_NOT_FOUND"));
    }

    @ExceptionHandler(DuplicateException.class)
    public ResponseEntity<CommonResponse<Void>> handleDuplicate(DuplicateException ex) {
        log.warn("DuplicateException: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(CommonResponse.error(ex.getMessage(), "DUPLICATE_RESOURCE"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<CommonResponse<Void>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .collect(Collectors.joining(", "));

        log.warn("Validation error: {}", message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(CommonResponse.error(message, "VALIDATION_ERROR"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<CommonResponse<Void>> handleGeneral(Exception ex) {
        log.error("Unexpected error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(CommonResponse.error("서버 내부 오류가 발생했습니다.", "INTERNAL_SERVER_ERROR"));
    }
}
```

## Security 설정 예시

### SecurityFilterChain 구현

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/auth/**", "/api/v1/public/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/v1/users/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### Authentication Entry Point 구현

```java
@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException authException) throws IOException {

        log.warn("Unauthorized access attempt: {}", authException.getMessage());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        CommonResponse<Void> errorResponse = CommonResponse.error(
            "인증이 필요합니다.",
            "AUTHENTICATION_REQUIRED"
        );

        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
```

### Access Denied Handler 구현

```java
@Component
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                      AccessDeniedException accessDeniedException) throws IOException {

        log.warn("Access denied: {}", accessDeniedException.getMessage());

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        CommonResponse<Void> errorResponse = CommonResponse.error(
            "접근 권한이 없습니다.",
            "ACCESS_DENIED"
        );

        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
```

### JWT Authentication Filter 구현

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {

        String token = resolveToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            try {
                String username = jwtTokenProvider.getUsername(token);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                log.warn("JWT authentication failed: {}", e.getMessage());
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```