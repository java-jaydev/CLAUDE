# Spring Boot Testing Guide

이 문서는 Spring Boot 프로젝트의 테스트 전략과 실제 테스트 코드 예시를 제공합니다.

## 테스트 전략

### 테스트 계층 구조

1. **Unit Test**: 개별 컴포넌트(Service, Repository) 단위 테스트
2. **Integration Test**: 여러 컴포넌트 간의 통합 테스트
3. **Web Layer Test**: Controller 계층 테스트
4. **End-to-End Test**: 전체 애플리케이션 통합 테스트

### 테스트 환경 설정

#### 테스트 프로파일 설정

`src/test/resources/application-test.yml`

```yaml
spring:
  profiles:
    active: test
  datasource:
    url: jdbc:h2:mem:testdb;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE
    username: sa
    password:
    driver-class-name: org.h2.Driver
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.H2Dialect
  sql:
    init:
      mode: embedded
  redis:
    host: localhost
    port: 6370 # 테스트용 Redis (실제는 embedded-redis 사용)

logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
```

#### 테스트용 Base 클래스

```java
@SpringBootTest
@ActiveProfiles("test")
@Transactional
@Rollback
public abstract class IntegrationTestBase {
    
    @Autowired
    protected TestEntityManager entityManager;
    
    protected void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }
}
```

## Unit Test 예시

### Service Layer Unit Test

```java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserQueryRepository userQueryRepository;

    @InjectMocks
    private UserService userService;

    @Test
    @DisplayName("사용자 ID로 조회 성공")
    void findById_Success() {
        // Given
        Long userId = 1L;
        User user = User.builder()
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        // When
        UserResponse response = userService.findById(userId);

        // Then
        assertThat(response.getName()).isEqualTo("홍길동");
        assertThat(response.getEmail()).isEqualTo("hong@example.com");
        verify(userRepository).findById(userId);
    }

    @Test
    @DisplayName("존재하지 않는 사용자 조회시 예외 발생")
    void findById_UserNotFound() {
        // Given
        Long userId = 999L;
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.findById(userId))
            .isInstanceOf(EntityNotFoundException.class)
            .hasMessage("사용자를 찾을 수 없습니다. ID: " + userId);
    }

    @Test
    @DisplayName("사용자 생성 성공")
    void createUser_Success() {
        // Given
        UserCreateRequest request = UserCreateRequest.builder()
            .name("홍길동")
            .email("hong@example.com")
            .build();

        User savedUser = User.builder()
            .id(1L)
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // When
        UserResponse response = userService.createUser(request);

        // Then
        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getName()).isEqualTo("홍길동");
        assertThat(response.getEmail()).isEqualTo("hong@example.com");
        
        verify(userRepository).existsByEmail(request.getEmail());
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("중복 이메일로 사용자 생성시 예외 발생")
    void createUser_DuplicateEmail() {
        // Given
        UserCreateRequest request = UserCreateRequest.builder()
            .name("홍길동")
            .email("duplicate@example.com")
            .build();

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.createUser(request))
            .isInstanceOf(DuplicateException.class)
            .hasMessage("이미 사용중인 이메일입니다: " + request.getEmail());

        verify(userRepository).existsByEmail(request.getEmail());
        verify(userRepository, never()).save(any(User.class));
    }
}
```

### Repository Unit Test (with ArgumentCaptor)

```java
@ExtendWith(MockitoExtension.class)
class UserServiceUnitTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    @Test
    @DisplayName("사용자 생성시 올바른 값으로 저장되는지 확인")
    void createUser_VerifyUserCreation() {
        // Given
        UserCreateRequest request = UserCreateRequest.builder()
            .name("홍길동")
            .email("hong@example.com")
            .build();

        User savedUser = User.builder()
            .id(1L)
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();

        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // When
        userService.createUser(request);

        // Then
        verify(userRepository).save(userCaptor.capture());
        User capturedUser = userCaptor.getValue();
        
        assertThat(capturedUser.getName()).isEqualTo("홍길동");
        assertThat(capturedUser.getEmail()).isEqualTo("hong@example.com");
        assertThat(capturedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(capturedUser.getRole()).isEqualTo(UserRole.USER);
    }
}
```

## Integration Test 예시

### Repository Integration Test

```java
@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("이메일로 사용자 존재 여부 확인")
    void existsByEmail() {
        // Given
        User user = User.builder()
            .name("홍길동")
            .email("test@example.com")
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();
        entityManager.persistAndFlush(user);

        // When
        boolean exists = userRepository.existsByEmail("test@example.com");
        boolean notExists = userRepository.existsByEmail("notfound@example.com");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("상태별 사용자 조회")
    void findByStatus() {
        // Given
        User activeUser = createUser("active@example.com", UserStatus.ACTIVE);
        User inactiveUser = createUser("inactive@example.com", UserStatus.INACTIVE);
        entityManager.persistAndFlush(activeUser);
        entityManager.persistAndFlush(inactiveUser);

        // When
        List<User> activeUsers = userRepository.findByStatus(UserStatus.ACTIVE);
        List<User> inactiveUsers = userRepository.findByStatus(UserStatus.INACTIVE);

        // Then
        assertThat(activeUsers).hasSize(1);
        assertThat(activeUsers.get(0).getEmail()).isEqualTo("active@example.com");
        
        assertThat(inactiveUsers).hasSize(1);
        assertThat(inactiveUsers.get(0).getEmail()).isEqualTo("inactive@example.com");
    }

    private User createUser(String email, UserStatus status) {
        return User.builder()
            .name("테스트 사용자")
            .email(email)
            .status(status)
            .role(UserRole.USER)
            .build();
    }
}
```

### QueryDSL Repository Test

```java
@DataJpaTest
@Import({QuerydslConfig.class, UserQueryRepository.class})
@ActiveProfiles("test")
class UserQueryRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserQueryRepository userQueryRepository;

    @Test
    @DisplayName("조건별 사용자 페이징 조회")
    void findByCondition() {
        // Given
        createTestUsers();
        
        UserSearchCondition condition = UserSearchCondition.builder()
            .name("홍")
            .status(UserStatus.ACTIVE)
            .build();
        
        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<User> result = userQueryRepository.findByCondition(condition, pageable);

        // Then
        assertThat(result.getContent()).hasSize(2);
        assertThat(result.getTotalElements()).isEqualTo(2);
        assertThat(result.getContent())
            .extracting(User::getName)
            .containsExactly("홍길동", "홍길순");
    }

    private void createTestUsers() {
        List<User> users = List.of(
            createUser("홍길동", "hong1@example.com", UserStatus.ACTIVE),
            createUser("홍길순", "hong2@example.com", UserStatus.ACTIVE),
            createUser("김철수", "kim@example.com", UserStatus.ACTIVE),
            createUser("홍길서", "hong3@example.com", UserStatus.INACTIVE)
        );
        
        users.forEach(entityManager::persist);
        entityManager.flush();
    }

    private User createUser(String name, String email, UserStatus status) {
        // ValidationUtil을 사용한 테스트 데이터 검증
        if (StringUtil.isEmpty(name) || !ValidationUtil.isValidEmail(email)) {
            throw new IllegalArgumentException("Invalid test data");
        }
        
        return User.builder()
            .name(name)
            .email(email)
            .status(status)
            .role(UserRole.USER)
            .createdAt(DateUtil.nowAsLocalDateTime())
            .build();
    }
}
```

## Web Layer Test 예시

### Controller Test

```java
@WebMvcTest(UserController.class)
@ActiveProfiles("test")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("사용자 조회 API 성공")
    void getUser_Success() throws Exception {
        // Given
        Long userId = 1L;
        UserResponse userResponse = UserResponse.builder()
            .id(userId)
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .build();

        when(userService.findById(userId)).thenReturn(userResponse);

        // When & Then
        mockMvc.perform(get("/api/v1/users/{id}", userId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.id").value(userId))
            .andExpect(jsonPath("$.data.name").value("홍길동"))
            .andExpect(jsonPath("$.data.email").value("hong@example.com"))
            .andDo(print());

        verify(userService).findById(userId);
    }

    @Test
    @DisplayName("사용자 생성 API 성공")
    void createUser_Success() throws Exception {
        // Given
        UserCreateRequest request = UserCreateRequest.builder()
            .name("홍길동")
            .email("hong@example.com")
            .build();

        UserResponse response = UserResponse.builder()
            .id(1L)
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .build();

        when(userService.createUser(any(UserCreateRequest.class))).thenReturn(response);

        // When & Then
        mockMvc.perform(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(request)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.name").value("홍길동"))
            .andExpect(jsonPath("$.data.email").value("hong@example.com"))
            .andDo(print());

        verify(userService).createUser(any(UserCreateRequest.class));
    }

    @Test
    @DisplayName("잘못된 요청 데이터로 사용자 생성시 400 에러")
    void createUser_ValidationError() throws Exception {
        // Given
        UserCreateRequest invalidRequest = UserCreateRequest.builder()
            .name("")  // 빈 이름
            .email("invalid-email")  // 잘못된 이메일 형식
            .build();

        // When & Then
        mockMvc.perform(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtil.toJson(invalidRequest)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
            .andDo(print());

        verify(userService, never()).createUser(any(UserCreateRequest.class));
    }

    @Test
    @DisplayName("존재하지 않는 사용자 조회시 404 에러")
    void getUser_NotFound() throws Exception {
        // Given
        Long userId = 999L;
        when(userService.findById(userId))
            .thenThrow(new EntityNotFoundException("사용자를 찾을 수 없습니다. ID: " + userId));

        // When & Then
        mockMvc.perform(get("/api/v1/users/{id}", userId))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.errorCode").value("ENTITY_NOT_FOUND"))
            .andDo(print());
    }
}
```

### Security Test

```java
@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class UserControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtTokenProvider jwtTokenProvider;

    @Test
    @DisplayName("인증 없이 보호된 API 접근시 401 에러")
    void accessProtectedApi_WithoutAuth_Returns401() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/v1/users/1"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("사용자 권한으로 사용자 정보 조회 성공")
    void getUser_WithUserRole_Success() throws Exception {
        // Given
        Long userId = 1L;
        UserResponse userResponse = UserResponse.builder()
            .id(userId)
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .build();

        when(userService.findById(userId)).thenReturn(userResponse);

        // When & Then
        mockMvc.perform(get("/api/v1/users/{id}", userId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.name").value("홍길동"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("관리자 권한으로 모든 API 접근 가능")
    void accessAdminApi_WithAdminRole_Success() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/v1/admin/users"))
            .andExpect(status().isOk());
    }
}
```

## TestContainers 통합 테스트

### TestContainers 설정

```java
@SpringBootTest
@ActiveProfiles("test")
@Testcontainers
class UserIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
        .withDatabaseName("testdb")
        .withUsername("test")
        .withPassword("test");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
        .withExposedPorts(6379);

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        
        registry.add("spring.redis.host", redis::getHost);
        registry.add("spring.redis.port", redis::getFirstMappedPort);
    }

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("사용자 생성 통합 테스트")
    @Transactional
    void createUser_IntegrationTest() {
        // Given
        UserCreateRequest request = UserCreateRequest.builder()
            .name("홍길동")
            .email("hong@example.com")
            .build();

        // When
        UserResponse response = userService.createUser(request);

        // Then
        assertThat(response.getId()).isNotNull();
        assertThat(response.getName()).isEqualTo("홍길동");

        // DB 검증
        Optional<User> savedUser = userRepository.findById(response.getId());
        assertThat(savedUser).isPresent();
        assertThat(savedUser.get().getEmail()).isEqualTo("hong@example.com");
    }

    @Test
    @DisplayName("캐시 동작 확인 통합 테스트")
    void cacheIntegrationTest() {
        // Given
        User user = User.builder()
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();
        User savedUser = userRepository.save(user);

        // When - 첫 번째 조회 (DB에서 조회)
        UserResponse first = userService.findById(savedUser.getId());
        
        // When - 두 번째 조회 (캐시에서 조회)
        UserResponse second = userService.findById(savedUser.getId());

        // Then
        assertThat(first.getName()).isEqualTo("홍길동");
        assertThat(second.getName()).isEqualTo("홍길동");
        // 캐시 검증은 실제 성능 테스트나 메트릭으로 확인
    }
}
```

## 성능 테스트

### JMeter 연계 테스트

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class PerformanceTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @LocalServerPort
    private int port;

    @Test
    @DisplayName("사용자 조회 API 성능 테스트")
    void userApiPerformanceTest() {
        // Given
        int numberOfRequests = 100;
        List<Long> responseTimes = new ArrayList<>();

        // When
        for (int i = 0; i < numberOfRequests; i++) {
            long startTime = System.currentTimeMillis();
            
            ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/api/v1/users/1", 
                String.class
            );
            
            long endTime = System.currentTimeMillis();
            responseTimes.add(endTime - startTime);
            
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        // Then
        double averageResponseTime = responseTimes.stream()
            .mapToLong(Long::longValue)
            .average()
            .orElse(0.0);
        
        long maxResponseTime = responseTimes.stream()
            .mapToLong(Long::longValue)
            .max()
            .orElse(0);

        System.out.println("Average response time: " + averageResponseTime + "ms");
        System.out.println("Max response time: " + maxResponseTime + "ms");
        
        // 성능 임계치 검증
        assertThat(averageResponseTime).isLessThan(100.0); // 평균 100ms 이하
        assertThat(maxResponseTime).isLessThan(500); // 최대 500ms 이하
    }
}
```

## 테스트 데이터 관리

### Test Fixtures

```java
public class UserTestFixtures {

    public static User createUser(String name, String email) {
        return User.builder()
            .name(name)
            .email(email)
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();
    }

    public static UserCreateRequest createUserRequest(String name, String email) {
        return UserCreateRequest.builder()
            .name(name)
            .email(email)
            .build();
    }

    public static List<User> createUsers(int count) {
        List<User> users = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            users.add(createUser("User" + i, "user" + i + "@example.com"));
        }
        return users;
    }
}
```

### ObjectMother Pattern

```java
public class UserMother {

    public static User defaultUser() {
        return User.builder()
            .name("홍길동")
            .email("hong@example.com")
            .status(UserStatus.ACTIVE)
            .role(UserRole.USER)
            .build();
    }

    public static User adminUser() {
        return User.builder()
            .name("관리자")
            .email("admin@example.com")
            .status(UserStatus.ACTIVE)
            .role(UserRole.ADMIN)
            .build();
    }

    public static User inactiveUser() {
        return defaultUser().toBuilder()
            .status(UserStatus.INACTIVE)
            .build();
    }
}
```

## 테스트 최적화

### 테스트 실행 최적화

```java
// 테스트 클래스별 애플리케이션 컨텍스트 공유
@SpringBootTest
@TestPropertySource(properties = {
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.datasource.url=jdbc:h2:mem:testdb"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
abstract class IntegrationTestBase {
    // 공통 테스트 설정
}

// 테스트 슬라이스 활용으로 빠른 테스트
@DataJpaTest
@Import(TestConfig.class)
class FastRepositoryTest {
    // Repository 계층만 테스트
}
```

### 병렬 테스트 실행

```properties
# junit-platform.properties
junit.jupiter.execution.parallel.enabled=true
junit.jupiter.execution.parallel.mode.default=concurrent
junit.jupiter.execution.parallel.config.strategy=dynamic
```

## 테스트 베스트 프랙티스

### 테스트 네이밍

- **Given-When-Then** 패턴 사용
- 테스트 메서드명에 테스트 상황과 기대 결과 명시
- `@DisplayName` 애노테이션으로 한글 설명 추가

### 테스트 격리

- 각 테스트는 독립적으로 실행 가능해야 함
- 테스트 간 상태 공유 금지
- `@Transactional`과 `@Rollback` 활용한 데이터 정리

### Assertion 최적화

```java
// AssertJ 활용
assertThat(users)
    .hasSize(3)
    .extracting(User::getName)
    .containsExactly("User1", "User2", "User3");

// 커스텀 Assertion
public static UserAssert assertThat(User actual) {
    return new UserAssert(actual);
}
```

이러한 테스트 전략과 예시를 통해 견고하고 신뢰할 수 있는 Spring Boot 애플리케이션을 개발할 수 있습니다.