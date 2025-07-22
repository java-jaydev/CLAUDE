# Spring Boot Patterns Guide

이 문서는 Spring Boot 프로젝트에서 사용하는 주요 패턴들과 설계 원칙을 다룹니다.

## DTO 패턴 가이드라인

### DTO 네이밍 컨벤션

**Request/Response 분리 방식 사용**

```java
// 생성 요청
UserCreateRequest
OrderCreateRequest

// 수정 요청
UserUpdateRequest
OrderUpdateRequest

// 응답
UserResponse
OrderResponse
UserListResponse  // 목록 조회용
OrderDetailResponse  // 상세 조회용
```

### DTO 클래스 구조

**기본 구조**

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class UserCreateRequest {

    @NotBlank(message = "이름은 필수입니다")
    @Size(max = 100, message = "이름은 100자를 초과할 수 없습니다")
    private String name;

    @Email(message = "올바른 이메일 형식이 아닙니다")
    @NotBlank(message = "이메일은 필수입니다")
    @Size(max = 255, message = "이메일은 255자를 초과할 수 없습니다")
    private String email;

    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
             message = "비밀번호는 8자 이상, 영문, 숫자, 특수문자를 포함해야 합니다")
    private String password;
}
```

**응답 DTO 구조**

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class UserResponse {

    private Long id;
    private String name;
    private String email;
    private UserStatus status;
    private UserRole role;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Entity to DTO 변환 메서드
    public static UserResponse from(User user) {
        return UserResponse.builder()
            .id(user.getId())
            .name(user.getName())
            .email(user.getEmail())
            .status(user.getStatus())
            .role(user.getRole())
            .createdAt(user.getCreatedAt())
            .updatedAt(user.getUpdatedAt())
            .build();
    }
}
```


### 페이징 응답 DTO

**페이징 응답 구조**

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class PageResponse<T> {

    private List<T> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
    private boolean first;
    private boolean last;
    private boolean hasNext;
    private boolean hasPrevious;

    public static <T> PageResponse<T> from(Page<T> page) {
        return PageResponse.<T>builder()
            .content(page.getContent())
            .page(page.getNumber())
            .size(page.getSize())
            .totalElements(page.getTotalElements())
            .totalPages(page.getTotalPages())
            .first(page.isFirst())
            .last(page.isLast())
            .hasNext(page.hasNext())
            .hasPrevious(page.hasPrevious())
            .build();
    }
}
```

### 중첩 DTO 처리

**복합 응답 DTO**

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class UserDetailResponse {

    private Long id;
    private String name;
    private String email;
    private UserStatus status;
    private List<OrderSummaryResponse> recentOrders;  // 별도 DTO 참조

    public static UserDetailResponse from(User user, List<Order> recentOrders) {
        List<OrderSummaryResponse> orderSummaries = recentOrders.stream()
            .map(order -> OrderSummaryResponse.builder()
                .orderId(order.getId())
                .orderNumber(order.getOrderNumber())
                .status(order.getStatus())
                .createdAt(order.getCreatedAt())
                .build())
            .collect(Collectors.toList());

        return UserDetailResponse.builder()
            .id(user.getId())
            .name(user.getName())
            .email(user.getEmail())
            .status(user.getStatus())
            .recentOrders(orderSummaries)
            .build();
    }
}

// OrderSummaryResponse - 별도 클래스로 분리
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class OrderSummaryResponse {
    private Long orderId;
    private String orderNumber;
    private OrderStatus status;
    private LocalDateTime createdAt;
}
```

## Repository 패턴

### JPA Repository 구조

**기본 Repository 인터페이스**

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    List<User> findByStatus(UserStatus status);
    
    @Query("SELECT u FROM User u WHERE u.name LIKE %:name%")
    List<User> findByNameContaining(@Param("name") String name);
}
```

### QueryDSL Custom Repository

**Custom Repository 인터페이스**

```java
public interface UserQueryRepository {
    Page<User> findByCondition(UserSearchCondition condition, Pageable pageable);
    List<UserListResponse> findUserList();
    List<User> findActiveUsersWithRecentOrders();
}
```

**QueryDSL 구현체**

```java
@Repository
@RequiredArgsConstructor
public class UserQueryRepositoryImpl implements UserQueryRepository {

    private final JPAQueryFactory queryFactory;

    @Override
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

    @Override
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

### Database Conventions

- **테이블명**: snake_case
- **컬럼명**: snake_case
- **Primary Key**: `id` (Long 타입)
- **생성/수정 시간**: `created_at`, `updated_at`
- **소프트 삭제**: `deleted_at`
- **Index 네이밍**: `idx_테이블명_컬럼명` 형식 (예: idx_users_email)
- **Foreign Key**: `fk_테이블명_참조테이블명` 형식 (예: fk_orders_users)
- **QueryDSL Q클래스**: static import를 통한 참조 사용

```java
import static net.thetelos.project.entity.QUser.user;
import static net.thetelos.project.entity.QOrder.order;

// 사용 예시
queryFactory.selectFrom(user)
    .where(user.email.eq("test@example.com"))
    .fetch();
```

- **JPA 애노테이션**: @Entity, @Table(name = "table_name"), @Column(name = "column_name") 명시적 사용
- **BaseEntity**: 공통 필드(id, 생성/수정 시간, 생성/수정자)는 BaseEntity 상속으로 관리
- **감사(Audit) 컬럼**: JPA Auditing 활용하여 자동 입력
  - `created_at`, `updated_at`: @CreatedDate, @LastModifiedDate
  - `created_by`, `updated_by`: @CreatedBy, @LastModifiedBy
- **테이블 주석**: @Table의 comment 속성 또는 @Comment 애노테이션 활용으로 테이블/컬럼 설명 추가

## Service 패턴

### Service Layer 구조

**기본 Service 패턴**

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

    private void validateDuplicateEmail(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateException("이미 사용중인 이메일입니다: " + email);
        }
    }
}
```

### Transaction 관리

**Transaction 패턴**

- 기본적으로 클래스에 `@Transactional(readOnly = true)` 선언
- 데이터 변경(등록, 수정, 삭제) 메서드에는 `@Transactional` 별도 지정
- 읽기 전용 트랜잭션으로 성능 최적화

### 도메인 서비스 분리

**도메인별 서비스 분리**

```java
// 사용자 관련 비즈니스 로직
@Service
public class UserService { ... }

// 주문 관련 비즈니스 로직
@Service 
public class OrderService { ... }

// 결제 관련 비즈니스 로직
@Service
public class PaymentService { ... }
```

## Controller 패턴

### REST Controller 구조

**기본 Controller 패턴 (Swagger 포함)**

```java
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Validated
@Slf4j
@Tag(name = "사용자 관리", description = "사용자 관리 API")
public class UserController {

    private final UserService userService;

    @Operation(summary = "사용자 조회", description = "사용자 ID로 사용자 정보를 조회합니다.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "조회 성공"),
        @ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음")
    })
    @GetMapping("/{id}")
    public ResponseEntity<CommonResponse<UserResponse>> getUser(
            @Parameter(description = "사용자 ID", required = true, example = "1")
            @PathVariable @Positive Long id) {
        UserResponse user = userService.findById(id);
        return ResponseEntity.ok(CommonResponse.success(user));
    }

    @Operation(summary = "사용자 등록", description = "새로운 사용자를 등록합니다.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "등록 성공"),
        @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터")
    })
    @PostMapping
    public ResponseEntity<CommonResponse<UserResponse>> createUser(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "사용자 등록 정보", 
                required = true
            )
            @RequestBody @Valid UserCreateRequest request) {
        UserResponse user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(CommonResponse.success(user));
    }

    @Operation(summary = "사용자 목록 조회", description = "조건에 따라 사용자 목록을 페이징 조회합니다.")
    @GetMapping
    public ResponseEntity<CommonResponse<PageResponse<UserResponse>>> getUsers(
            @Parameter(description = "검색 조건") @ModelAttribute UserSearchCondition condition,
            @Parameter(hidden = true) Pageable pageable) {
        Page<UserResponse> users = userService.findUsers(condition, pageable);
        PageResponse<UserResponse> response = PageResponse.from(users);
        return ResponseEntity.ok(CommonResponse.success(response));
    }

    @Operation(summary = "사용자 정보 수정", description = "현재 로그인한 사용자의 정보를 수정합니다.")
    @PutMapping("/me")
    public ResponseEntity<CommonResponse<UserResponse>> updateMyInfo(
            @RequestBody @Valid UserUpdateRequest request,
            @Parameter(hidden = true) Authentication authentication) {
        UserResponse user = userService.updateMyInfo(request, authentication.getName());
        return ResponseEntity.ok(CommonResponse.success(user));
    }

    @Operation(summary = "사용자 삭제", description = "관리자 권한으로 사용자를 삭제합니다.")
    @DeleteMapping("/{id}")
    public ResponseEntity<CommonResponse<Void>> deleteUser(
            @Parameter(description = "사용자 ID", required = true) @PathVariable Long id,
            @Parameter(hidden = true) Principal principal,
            @Parameter(hidden = true) HttpServletRequest request,
            @Parameter(hidden = true) HttpServletResponse response) {
        userService.deleteUser(id, principal.getName());
        return ResponseEntity.ok(CommonResponse.success());
    }
}
```

### API Response 표준화

**공통 응답 형식**

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

## Entity 패턴

### BaseEntity 설계

#### 1. BaseTimeEntity - 시간 추적용

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

#### 2. BaseEntity - 완전한 감사 추적용

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

#### BaseEntity 선택 가이드

**BaseTimeEntity 사용 케이스:**
- 마스터 데이터 (코드, 카테고리, 설정 등)
- 로그 데이터 (접근 기록, 시스템 로그 등)
- 감사자 정보 불필요한 단순 엔티티

**BaseEntity 사용 케이스:**
- 사용자 관련 데이터 (회원, 게시글, 주문 등)
- 비즈니스 핵심 데이터
- 감사 추적이 중요한 모든 엔티티

### Entity 설계 원칙

**도메인 Entity 예시**

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

    public void activate() {
        this.status = UserStatus.ACTIVE;
    }

    public void deactivate() {
        this.status = UserStatus.INACTIVE;
    }
}
```

### Enum 활용

**상태 관리용 Enum**

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

### Converter 패턴

**Enum Converter 예시**

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

## Best Practices

### 코딩 컨벤션

- Constructor Injection 우선 사용 (필드 주입 지양)
- `@Transactional` 적절한 위치에 배치
- **QueryDSL 활용**: Repository 패턴과 QueryDSL Custom Repository 조합으로 타입 안전한 동적 쿼리 구현
- **Validation**: @Valid, @Validated를 활용한 요청 데이터 검증
- **Exception Handling**: @ControllerAdvice와 @ExceptionHandler를 활용한 글로벌 예외 처리
- **API Response**: 표준 응답 형식(CommonResponse<T>) 사용으로 일관된 API 응답 구조 유지
- **로깅**: Lombok의 @Slf4j를 활용하여 처리, 민감정보 로깅 금지
- **Bean Validation 3.0**: @NotNull, @NotBlank, @Size 등 표준 Validation 애노테이션 활용
- **JPA Auditing**: @EnableJpaAuditing을 통한 감사 컬럼 자동 관리, BaseEntity 상속 구조 활용

### 성능 고려사항

- N+1 문제 방지 (Fetch Join, EntityGraph 사용)
- 필요한 컬럼만 조회 (DTO Projection 활용)
- 적절한 인덱스 설계
- 캐싱 전략 수립
- Connection Pool 최적화