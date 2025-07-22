# Utility Classes Guide

이 문서는 Spring Boot 프로젝트에서 자주 사용하는 유틸리티 클래스들의 설계 원칙과 구현 예시를 제공합니다.

## Util 패키지 구조

```
src/main/java/net/thetelos/project/util/
├── DateUtil.java           # 날짜/시간 처리
├── StringUtil.java         # 문자열 처리
├── ValidationUtil.java     # 유효성 검증
├── PasswordUtil.java       # 비밀번호 처리
├── JsonUtil.java           # JSON 처리
├── FileUtil.java           # 파일 처리
├── CryptoUtil.java         # 암호화/복호화
├── RandomUtil.java         # 랜덤값 생성
└── CollectionUtil.java     # 컬렉션 처리
```

## 날짜/시간 유틸리티

### DateUtil.java

```java
@Slf4j
public final class DateUtil {

    private DateUtil() {
        throw new IllegalStateException("Utility class");
    }

    // 기본 포맷터들
    public static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    public static final DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    public static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    /**
     * 현재 날짜를 문자열로 반환
     */
    public static String today() {
        return LocalDate.now().format(DATE_FORMATTER);
    }

    /**
     * 현재 날짜시간을 문자열로 반환
     */
    public static String now() {
        return LocalDateTime.now().format(DATETIME_FORMATTER);
    }

    /**
     * 타임스탬프 형식으로 현재 시간 반환
     */
    public static String timestamp() {
        return LocalDateTime.now().format(TIMESTAMP_FORMATTER);
    }

    /**
     * 문자열을 LocalDate로 변환
     */
    public static LocalDate parseDate(String dateString) {
        try {
            return LocalDate.parse(dateString, DATE_FORMATTER);
        } catch (DateTimeParseException e) {
            log.warn("날짜 파싱 실패: {}", dateString);
            throw new IllegalArgumentException("유효하지 않은 날짜 형식입니다: " + dateString);
        }
    }

    /**
     * 문자열을 LocalDateTime으로 변환
     */
    public static LocalDateTime parseDateTime(String dateTimeString) {
        try {
            return LocalDateTime.parse(dateTimeString, DATETIME_FORMATTER);
        } catch (DateTimeParseException e) {
            log.warn("날짜시간 파싱 실패: {}", dateTimeString);
            throw new IllegalArgumentException("유효하지 않은 날짜시간 형식입니다: " + dateTimeString);
        }
    }

    /**
     * 두 날짜 사이의 일수 계산
     */
    public static long daysBetween(LocalDate startDate, LocalDate endDate) {
        return ChronoUnit.DAYS.between(startDate, endDate);
    }

    /**
     * 날짜가 특정 범위 내에 있는지 확인
     */
    public static boolean isWithinRange(LocalDate date, LocalDate startDate, LocalDate endDate) {
        return !date.isBefore(startDate) && !date.isAfter(endDate);
    }

    /**
     * 월의 시작일과 마지막일 반환
     */
    public static Pair<LocalDate, LocalDate> getMonthRange(YearMonth yearMonth) {
        LocalDate startDate = yearMonth.atDay(1);
        LocalDate endDate = yearMonth.atEndOfMonth();
        return Pair.of(startDate, endDate);
    }

    /**
     * 현재 LocalDateTime 반환
     */
    public static LocalDateTime nowAsLocalDateTime() {
        return LocalDateTime.now();
    }
}
```

## 문자열 유틸리티

### StringUtil.java

```java
@Slf4j
public final class StringUtil {

    private StringUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * 문자열이 비어있거나 null인지 확인 (Spring의 StringUtils.hasText와 유사)
     */
    public static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * 문자열이 비어있지 않은지 확인
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * 문자열을 마스킹 처리
     */
    public static String mask(String str, int startIndex, int endIndex, char maskChar) {
        if (isEmpty(str) || startIndex < 0 || endIndex >= str.length() || startIndex > endIndex) {
            return str;
        }

        StringBuilder sb = new StringBuilder(str);
        for (int i = startIndex; i <= endIndex; i++) {
            sb.setCharAt(i, maskChar);
        }
        return sb.toString();
    }

    /**
     * 이메일 마스킹 처리
     */
    public static String maskEmail(String email) {
        if (isEmpty(email) || !email.contains("@")) {
            return email;
        }

        String[] parts = email.split("@");
        String localPart = parts[0];
        String domainPart = parts[1];

        if (localPart.length() <= 2) {
            return email;
        }

        String maskedLocal = localPart.charAt(0) + 
                           "*".repeat(localPart.length() - 2) + 
                           localPart.charAt(localPart.length() - 1);
        return maskedLocal + "@" + domainPart;
    }

    /**
     * 전화번호 마스킹 처리
     */
    public static String maskPhoneNumber(String phoneNumber) {
        if (isEmpty(phoneNumber)) {
            return phoneNumber;
        }

        String cleanNumber = phoneNumber.replaceAll("[^0-9]", "");
        if (cleanNumber.length() != 11) {
            return phoneNumber;
        }

        return cleanNumber.substring(0, 3) + "-****-" + cleanNumber.substring(7);
    }

    /**
     * 문자열을 카멜케이스로 변환
     */
    public static String toCamelCase(String str, String delimiter) {
        if (isEmpty(str)) {
            return str;
        }

        String[] words = str.split(delimiter);
        StringBuilder result = new StringBuilder(words[0].toLowerCase());

        for (int i = 1; i < words.length; i++) {
            result.append(capitalize(words[i].toLowerCase()));
        }

        return result.toString();
    }

    /**
     * 첫 글자를 대문자로 변환
     */
    public static String capitalize(String str) {
        if (isEmpty(str)) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }

    /**
     * 랜덤 문자열 생성
     */
    public static String generateRandomString(int length) {
        return generateRandomString(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    }

    /**
     * 지정된 문자셋으로 랜덤 문자열 생성
     */
    public static String generateRandomString(int length, String charset) {
        if (length <= 0 || isEmpty(charset)) {
            throw new IllegalArgumentException("길이는 0보다 크고 문자셋은 비어있지 않아야 합니다");
        }

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(charset.charAt(random.nextInt(charset.length())));
        }
        return sb.toString();
    }

    /**
     * Validation 에러 메시지 포맷팅
     */
    public static String formatValidationErrors(BindingResult bindingResult) {
        if (bindingResult == null || !bindingResult.hasErrors()) {
            return "";
        }

        return bindingResult.getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
    }

    /**
     * List를 문자열로 조인
     */
    public static String joinMessages(List<?> items, Function<?, String> mapper) {
        if (CollectionUtil.isEmpty(items)) {
            return "";
        }

        return items.stream()
                .map(mapper::apply)
                .collect(Collectors.joining(", "));
    }
}
```

## 유효성 검증 유틸리티

### ValidationUtil.java

```java
@Slf4j
public final class ValidationUtil {

    private ValidationUtil() {
        throw new IllegalStateException("Utility class");
    }

    // 정규식 패턴들
    private static final Pattern EMAIL_PATTERN = 
        Pattern.compile("^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$");
    
    private static final Pattern PHONE_PATTERN = 
        Pattern.compile("^01[0-9]-?[0-9]{4}-?[0-9]{4}$");
    
    private static final Pattern PASSWORD_PATTERN = 
        Pattern.compile("^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$");

    /**
     * 이메일 형식 검증
     */
    public static boolean isValidEmail(String email) {
        return StringUtil.isNotEmpty(email) && EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * 전화번호 형식 검증
     */
    public static boolean isValidPhoneNumber(String phoneNumber) {
        if (StringUtil.isEmpty(phoneNumber)) {
            return false;
        }
        String cleanNumber = phoneNumber.replaceAll("[^0-9]", "");
        return PHONE_PATTERN.matcher(phoneNumber).matches() || 
               (cleanNumber.length() == 11 && cleanNumber.startsWith("01"));
    }

    /**
     * 비밀번호 강도 검증 (8자 이상, 영문, 숫자, 특수문자 포함)
     */
    public static boolean isValidPassword(String password) {
        return StringUtil.isNotEmpty(password) && PASSWORD_PATTERN.matcher(password).matches();
    }

    /**
     * 사업자등록번호 검증
     */
    public static boolean isValidBusinessNumber(String businessNumber) {
        if (StringUtil.isEmpty(businessNumber)) {
            return false;
        }

        String cleanNumber = businessNumber.replaceAll("[^0-9]", "");
        if (cleanNumber.length() != 10) {
            return false;
        }

        // 체크섬 계산
        int[] weights = {1, 3, 7, 1, 3, 7, 1, 3, 5};
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            sum += Character.getNumericValue(cleanNumber.charAt(i)) * weights[i];
        }
        
        int checkDigit = (10 - (sum % 10)) % 10;
        return checkDigit == Character.getNumericValue(cleanNumber.charAt(9));
    }

    /**
     * 주민등록번호 유효성 검증 (마스킹된 형태도 고려)
     */
    public static boolean isValidResidentNumber(String residentNumber) {
        if (StringUtil.isEmpty(residentNumber)) {
            return false;
        }

        String cleanNumber = residentNumber.replaceAll("[^0-9*]", "");
        if (cleanNumber.length() != 13) {
            return false;
        }

        // 마스킹된 경우는 앞 6자리만 검증
        if (cleanNumber.contains("*")) {
            String birthPart = cleanNumber.substring(0, 6);
            return birthPart.matches("\\d{6}");
        }

        // 전체 검증 로직 (실제 프로젝트에서는 보안상 주의 필요)
        return cleanNumber.matches("\\d{13}");
    }

    /**
     * URL 형식 검증
     */
    public static boolean isValidUrl(String url) {
        if (StringUtil.isEmpty(url)) {
            return false;
        }

        try {
            new URL(url);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * IPv4 주소 검증
     */
    public static boolean isValidIpAddress(String ip) {
        if (StringUtil.isEmpty(ip)) {
            return false;
        }

        try {
            InetAddress.getByName(ip);
            return ip.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
```

## 보안 유틸리티

### SecurityUtil.java

```java
@Slf4j
public final class SecurityUtil {

    private SecurityUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * 현재 인증된 사용자의 Authentication 객체 반환
     */
    public static Optional<Authentication> getCurrentAuthentication() {
        SecurityContext context = SecurityContextHolder.getContext();
        return Optional.ofNullable(context.getAuthentication())
                      .filter(auth -> auth.isAuthenticated() && 
                                    !"anonymousUser".equals(auth.getPrincipal()));
    }

    /**
     * 현재 인증된 사용자의 username(이메일) 반환
     */
    public static Optional<String> getCurrentUsername() {
        return getCurrentAuthentication()
                .map(Authentication::getName);
    }

    /**
     * 현재 인증된 사용자의 ID 반환 (UserDetails 커스텀 구현체에서)
     */
    public static Optional<Long> getCurrentUserId() {
        return getCurrentAuthentication()
                .map(Authentication::getPrincipal)
                .filter(principal -> principal instanceof UserPrincipal)
                .map(principal -> ((UserPrincipal) principal).getId());
    }

    /**
     * 현재 사용자가 특정 권한을 가지고 있는지 확인
     */
    public static boolean hasAuthority(String authority) {
        return getCurrentAuthentication()
                .map(Authentication::getAuthorities)
                .map(authorities -> authorities.stream()
                    .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(authority)))
                .orElse(false);
    }

    /**
     * 현재 사용자가 특정 역할을 가지고 있는지 확인
     */
    public static boolean hasRole(String role) {
        String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        return hasAuthority(roleWithPrefix);
    }

    /**
     * 현재 사용자가 여러 권한 중 하나라도 가지고 있는지 확인
     */
    public static boolean hasAnyAuthority(String... authorities) {
        return Arrays.stream(authorities)
                    .anyMatch(SecurityUtil::hasAuthority);
    }

    /**
     * 현재 사용자가 여러 역할 중 하나라도 가지고 있는지 확인
     */
    public static boolean hasAnyRole(String... roles) {
        return Arrays.stream(roles)
                    .anyMatch(SecurityUtil::hasRole);
    }

    /**
     * 현재 사용자가 모든 권한을 가지고 있는지 확인
     */
    public static boolean hasAllAuthorities(String... authorities) {
        return Arrays.stream(authorities)
                    .allMatch(SecurityUtil::hasAuthority);
    }

    /**
     * 현재 사용자가 익명 사용자인지 확인
     */
    public static boolean isAnonymous() {
        return getCurrentAuthentication()
                .map(auth -> "anonymousUser".equals(auth.getPrincipal()))
                .orElse(true);
    }

    /**
     * 현재 사용자가 인증된 사용자인지 확인
     */
    public static boolean isAuthenticated() {
        return !isAnonymous();
    }

    /**
     * 현재 사용자가 관리자인지 확인
     */
    public static boolean isAdmin() {
        return hasRole("ADMIN");
    }

    /**
     * IP 주소 추출 (X-Forwarded-For, X-Real-IP 헤더 고려)
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

        String[] headerNames = {
            "X-Forwarded-For",
            "X-Real-IP", 
            "X-Original-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (StringUtil.isNotEmpty(ip) && !"unknown".equalsIgnoreCase(ip)) {
                // X-Forwarded-For는 여러 IP가 콤마로 구분될 수 있음
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                if (isValidIpAddress(ip)) {
                    return ip;
                }
            }
        }

        // 헤더에서 찾지 못한 경우 기본 Remote Address 사용
        String remoteAddr = request.getRemoteAddr();
        return StringUtil.isNotEmpty(remoteAddr) ? remoteAddr : "unknown";
    }

    /**
     * User-Agent 정보 추출 및 정리
     */
    public static String getUserAgent(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        
        String userAgent = request.getHeader("User-Agent");
        return StringUtil.isNotEmpty(userAgent) ? userAgent : "unknown";
    }

    /**
     * 현재 사용자가 특정 리소스에 대한 접근 권한이 있는지 확인
     * @param resourceOwnerId 리소스 소유자 ID
     * @param allowedRoles 접근 허용 역할들
     */
    public static boolean canAccessResource(Long resourceOwnerId, String... allowedRoles) {
        // 관리자는 모든 리소스 접근 가능
        if (hasAnyRole(allowedRoles)) {
            return true;
        }

        // 리소스 소유자 본인인지 확인
        return getCurrentUserId()
                .map(currentUserId -> currentUserId.equals(resourceOwnerId))
                .orElse(false);
    }

    /**
     * JWT 토큰에서 클레임 추출
     */
    public static Optional<String> getClaimFromToken(String token, String claimName) {
        try {
            return getCurrentAuthentication()
                    .filter(auth -> auth.getCredentials() instanceof String)
                    .map(auth -> (String) auth.getCredentials())
                    .or(() -> Optional.ofNullable(token))
                    .map(jwt -> extractClaimFromJwt(jwt, claimName));
        } catch (Exception e) {
            log.warn("JWT 토큰에서 클레임 추출 실패: claim={}, error={}", claimName, e.getMessage());
            return Optional.empty();
        }
    }

    private static String extractClaimFromJwt(String token, String claimName) {
        // JWT 파싱 로직 (실제로는 JWT 라이브러리 사용)
        // 여기서는 예시로만 작성
        return null;
    }

    private static boolean isValidIpAddress(String ip) {
        if (StringUtil.isEmpty(ip)) {
            return false;
        }

        // IPv4 패턴 확인
        String ipv4Pattern = 
            "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

        return ip.matches(ipv4Pattern) && 
               !ip.equals("127.0.0.1") && 
               !ip.equals("0:0:0:0:0:0:0:1");
    }
}
```

### JwtUtil.java

```java
@Slf4j
public final class JwtUtil {

    private JwtUtil() {
        throw new IllegalStateException("Utility class");
    }

    // JWT 설정값들 (실제로는 @Value나 @ConfigurationProperties로 주입)
    private static final String SECRET_KEY = "your-secret-key"; // 실제로는 환경변수에서 로드
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30; // 30분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7; // 7일
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_STRING = "Authorization";

    /**
     * Access Token 생성
     */
    public static String generateAccessToken(String username, Collection<String> authorities) {
        return generateToken(username, authorities, ACCESS_TOKEN_EXPIRE_TIME, TokenType.ACCESS);
    }

    /**
     * Refresh Token 생성
     */
    public static String generateRefreshToken(String username) {
        return generateToken(username, Collections.emptyList(), REFRESH_TOKEN_EXPIRE_TIME, TokenType.REFRESH);
    }

    /**
     * 토큰 생성 (공통 메서드)
     */
    private static String generateToken(String username, Collection<String> authorities, 
                                      long expireTime, TokenType tokenType) {
        try {
            Date expiryDate = new Date(System.currentTimeMillis() + expireTime);

            return Jwts.builder()
                    .setSubject(username)
                    .claim("authorities", String.join(",", authorities))
                    .claim("type", tokenType.name())
                    .setIssuedAt(new Date())
                    .setExpiration(expiryDate)
                    .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                    .compact();
        } catch (Exception e) {
            log.error("JWT 토큰 생성 실패: username={}, error={}", username, e.getMessage());
            throw new RuntimeException("토큰 생성에 실패했습니다", e);
        }
    }

    /**
     * 토큰에서 username 추출
     */
    public static String getUsernameFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    /**
     * 토큰에서 권한 목록 추출
     */
    public static List<String> getAuthoritiesFromToken(String token) {
        String authorities = (String) getClaimsFromToken(token).get("authorities");
        return StringUtil.isNotEmpty(authorities) ? 
               Arrays.asList(authorities.split(",")) : 
               Collections.emptyList();
    }

    /**
     * 토큰 타입 확인
     */
    public static TokenType getTokenType(String token) {
        String type = (String) getClaimsFromToken(token).get("type");
        return TokenType.valueOf(type);
    }

    /**
     * 토큰 유효성 검증
     */
    public static boolean validateToken(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            return !isTokenExpired(claims);
        } catch (Exception e) {
            log.debug("JWT 토큰 검증 실패: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Access Token인지 확인
     */
    public static boolean isAccessToken(String token) {
        try {
            return getTokenType(token) == TokenType.ACCESS;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Refresh Token인지 확인
     */
    public static boolean isRefreshToken(String token) {
        try {
            return getTokenType(token) == TokenType.REFRESH;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 토큰 만료시간 반환
     */
    public static Date getExpirationDateFromToken(String token) {
        return getClaimsFromToken(token).getExpiration();
    }

    /**
     * 토큰이 곧 만료되는지 확인 (5분 이내)
     */
    public static boolean isTokenExpiringSoon(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            long timeUntilExpiry = expiration.getTime() - System.currentTimeMillis();
            return timeUntilExpiry < (5 * 60 * 1000); // 5분
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * HttpServletRequest에서 토큰 추출
     */
    public static Optional<String> extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_STRING);
        if (StringUtil.isNotEmpty(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return Optional.of(bearerToken.substring(TOKEN_PREFIX.length()));
        }
        return Optional.empty();
    }

    /**
     * 토큰을 블랙리스트에 추가하기 위한 고유 식별자 생성
     */
    public static String generateTokenIdentifier(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            return DigestUtils.sha256Hex(claims.getSubject() + claims.getIssuedAt().getTime());
        } catch (Exception e) {
            log.warn("토큰 식별자 생성 실패: {}", e.getMessage());
            return DigestUtils.sha256Hex(token);
        }
    }

    private static Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                  .setSigningKey(SECRET_KEY)
                  .parseClaimsJws(token)
                  .getBody();
    }

    private static boolean isTokenExpired(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration.before(new Date());
    }

    public enum TokenType {
        ACCESS, REFRESH
    }
}
```

## 비밀번호 유틸리티

### PasswordUtil.java

```java
@Slf4j
public final class PasswordUtil {

    private PasswordUtil() {
        throw new IllegalStateException("Utility class");
    }

    private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // 임시 비밀번호용 문자셋
    private static final String TEMP_PASSWORD_CHARS = 
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";

    /**
     * 비밀번호 암호화
     */
    public static String encode(String rawPassword) {
        if (StringUtil.isEmpty(rawPassword)) {
            throw new IllegalArgumentException("비밀번호는 비어있을 수 없습니다");
        }
        return PASSWORD_ENCODER.encode(rawPassword);
    }

    /**
     * 비밀번호 검증
     */
    public static boolean matches(String rawPassword, String encodedPassword) {
        if (StringUtil.isEmpty(rawPassword) || StringUtil.isEmpty(encodedPassword)) {
            return false;
        }
        return PASSWORD_ENCODER.matches(rawPassword, encodedPassword);
    }

    /**
     * 임시 비밀번호 생성 (8자리, 영문대소문자 + 숫자 + 특수문자)
     */
    public static String generateTemporaryPassword() {
        return generateTemporaryPassword(8);
    }

    /**
     * 지정 길이의 임시 비밀번호 생성
     */
    public static String generateTemporaryPassword(int length) {
        if (length < 4) {
            throw new IllegalArgumentException("임시 비밀번호는 최소 4자리 이상이어야 합니다");
        }

        StringBuilder password = new StringBuilder();
        
        // 각 문자 타입별로 최소 1개씩 포함
        password.append(getRandomChar("ABCDEFGHJKLMNPQRSTUVWXYZ")); // 대문자
        password.append(getRandomChar("abcdefghijkmnpqrstuvwxyz")); // 소문자
        password.append(getRandomChar("23456789")); // 숫자
        password.append(getRandomChar("!@#$%")); // 특수문자

        // 나머지 길이만큼 랜덤 문자 추가
        for (int i = 4; i < length; i++) {
            password.append(getRandomChar(TEMP_PASSWORD_CHARS));
        }

        // 문자열 섞기
        return shuffleString(password.toString());
    }

    /**
     * 비밀번호 강도 계산 (0-100점)
     */
    public static int calculatePasswordStrength(String password) {
        if (StringUtil.isEmpty(password)) {
            return 0;
        }

        int score = 0;

        // 길이 점수 (최대 25점)
        int length = password.length();
        if (length >= 8) score += 25;
        else if (length >= 6) score += 15;
        else if (length >= 4) score += 10;

        // 문자 타입 점수 (각각 15점씩, 최대 60점)
        if (password.matches(".*[a-z].*")) score += 15; // 소문자
        if (password.matches(".*[A-Z].*")) score += 15; // 대문자
        if (password.matches(".*\\d.*")) score += 15;   // 숫자
        if (password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) score += 15; // 특수문자

        // 복잡도 보너스 (최대 15점)
        if (password.length() >= 12) score += 5;
        if (password.matches(".*[!@#$%^&*(),.?\":{}|<>].*") && password.length() >= 10) score += 5;
        if (hasNoRepeatingChars(password)) score += 5;

        return Math.min(100, score);
    }

    private static char getRandomChar(String chars) {
        return chars.charAt(SECURE_RANDOM.nextInt(chars.length()));
    }

    private static String shuffleString(String str) {
        char[] array = str.toCharArray();
        for (int i = array.length - 1; i > 0; i--) {
            int j = SECURE_RANDOM.nextInt(i + 1);
            char temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
        return new String(array);
    }

    private static boolean hasNoRepeatingChars(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) && 
                password.charAt(i) == password.charAt(i + 2)) {
                return false;
            }
        }
        return true;
    }

    /**
     * PasswordEncoder 인스턴스 반환 (일관된 설정 사용)
     */
    public static PasswordEncoder getPasswordEncoder() {
        return PASSWORD_ENCODER;
    }
}
```

## JSON 유틸리티

### JsonUtil.java

```java
@Slf4j
public final class JsonUtil {

    private JsonUtil() {
        throw new IllegalStateException("Utility class");
    }

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    /**
     * 객체를 JSON 문자열로 변환
     */
    public static String toJson(Object object) {
        try {
            return OBJECT_MAPPER.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            log.error("JSON 직렬화 실패: {}", e.getMessage());
            throw new RuntimeException("JSON 직렬화에 실패했습니다", e);
        }
    }

    /**
     * JSON 문자열을 객체로 변환
     */
    public static <T> T fromJson(String json, Class<T> valueType) {
        if (StringUtil.isEmpty(json)) {
            return null;
        }

        try {
            return OBJECT_MAPPER.readValue(json, valueType);
        } catch (JsonProcessingException e) {
            log.error("JSON 역직렬화 실패: {}", e.getMessage());
            throw new RuntimeException("JSON 역직렬화에 실패했습니다", e);
        }
    }

    /**
     * JSON 문자열을 제네릭 타입으로 변환
     */
    public static <T> T fromJson(String json, TypeReference<T> typeReference) {
        if (StringUtil.isEmpty(json)) {
            return null;
        }

        try {
            return OBJECT_MAPPER.readValue(json, typeReference);
        } catch (JsonProcessingException e) {
            log.error("JSON 역직렬화 실패: {}", e.getMessage());
            throw new RuntimeException("JSON 역직렬화에 실패했습니다", e);
        }
    }

    /**
     * 예쁘게 포맷된 JSON 문자열 생성
     */
    public static String toPrettyJson(Object object) {
        try {
            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
                                .writeValueAsString(object);
        } catch (JsonProcessingException e) {
            log.error("JSON pretty print 실패: {}", e.getMessage());
            throw new RuntimeException("JSON pretty print에 실패했습니다", e);
        }
    }

    /**
     * JSON 유효성 검증
     */
    public static boolean isValidJson(String json) {
        if (StringUtil.isEmpty(json)) {
            return false;
        }

        try {
            OBJECT_MAPPER.readTree(json);
            return true;
        } catch (JsonProcessingException e) {
            return false;
        }
    }

    /**
     * Object를 Map으로 변환
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> objectToMap(Object object) {
        return OBJECT_MAPPER.convertValue(object, Map.class);
    }

    /**
     * Map을 Object로 변환
     */
    public static <T> T mapToObject(Map<String, Object> map, Class<T> valueType) {
        return OBJECT_MAPPER.convertValue(map, valueType);
    }
}
```

## 파일 유틸리티

### FileUtil.java

```java
@Slf4j
public final class FileUtil {

    private FileUtil() {
        throw new IllegalStateException("Utility class");
    }

    // 허용된 파일 확장자
    private static final Set<String> ALLOWED_IMAGE_EXTENSIONS = 
        Set.of("jpg", "jpeg", "png", "gif", "bmp", "webp");
    
    private static final Set<String> ALLOWED_DOCUMENT_EXTENSIONS = 
        Set.of("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt");

    /**
     * 파일 확장자 추출
     */
    public static String getFileExtension(String filename) {
        if (StringUtil.isEmpty(filename)) {
            return "";
        }
        
        int lastDotIndex = filename.lastIndexOf(".");
        if (lastDotIndex == -1 || lastDotIndex == filename.length() - 1) {
            return "";
        }
        
        return filename.substring(lastDotIndex + 1).toLowerCase();
    }

    /**
     * 파일명에서 확장자 제거
     */
    public static String removeFileExtension(String filename) {
        if (StringUtil.isEmpty(filename)) {
            return filename;
        }
        
        int lastDotIndex = filename.lastIndexOf(".");
        return lastDotIndex == -1 ? filename : filename.substring(0, lastDotIndex);
    }

    /**
     * 안전한 파일명 생성 (특수문자 제거)
     */
    public static String sanitizeFilename(String filename) {
        if (StringUtil.isEmpty(filename)) {
            return filename;
        }
        
        // 위험한 문자들 제거 또는 대체
        return filename.replaceAll("[^a-zA-Z0-9가-힣._-]", "_")
                      .replaceAll("_{2,}", "_")
                      .replaceAll("^_|_$", "");
    }

    /**
     * 고유한 파일명 생성
     */
    public static String generateUniqueFilename(String originalFilename) {
        String extension = getFileExtension(originalFilename);
        String baseName = removeFileExtension(originalFilename);
        String timestamp = DateUtil.timestamp();
        String randomSuffix = StringUtil.generateRandomString(6);
        
        return sanitizeFilename(baseName) + "_" + timestamp + "_" + randomSuffix + 
               (StringUtil.isNotEmpty(extension) ? "." + extension : "");
    }

    /**
     * 이미지 파일 여부 확인
     */
    public static boolean isImageFile(String filename) {
        String extension = getFileExtension(filename);
        return ALLOWED_IMAGE_EXTENSIONS.contains(extension);
    }

    /**
     * 문서 파일 여부 확인
     */
    public static boolean isDocumentFile(String filename) {
        String extension = getFileExtension(filename);
        return ALLOWED_DOCUMENT_EXTENSIONS.contains(extension);
    }

    /**
     * 파일 크기를 사람이 읽기 쉬운 형태로 변환
     */
    public static String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    /**
     * MultipartFile이 비어있는지 확인
     */
    public static boolean isEmpty(MultipartFile file) {
        return file == null || file.isEmpty() || file.getSize() == 0;
    }

    /**
     * 파일 업로드 유효성 검증
     */
    public static void validateUploadFile(MultipartFile file, long maxSize, Set<String> allowedExtensions) {
        if (isEmpty(file)) {
            throw new IllegalArgumentException("업로드할 파일이 없습니다");
        }

        if (file.getSize() > maxSize) {
            throw new IllegalArgumentException(
                String.format("파일 크기가 너무 큽니다. 최대 크기: %s", formatFileSize(maxSize)));
        }

        String extension = getFileExtension(file.getOriginalFilename());
        if (!allowedExtensions.contains(extension)) {
            throw new IllegalArgumentException(
                String.format("허용되지 않은 파일 형식입니다. 허용 형식: %s", allowedExtensions));
        }
    }
}
```

## 컬렉션 유틸리티

### CollectionUtil.java

```java
public final class CollectionUtil {

    private CollectionUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * 컬렉션이 비어있는지 확인
     */
    public static boolean isEmpty(Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }

    /**
     * 컬렉션이 비어있지 않은지 확인
     */
    public static boolean isNotEmpty(Collection<?> collection) {
        return !isEmpty(collection);
    }

    /**
     * Map이 비어있는지 확인
     */
    public static boolean isEmpty(Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    /**
     * Map이 비어있지 않은지 확인
     */
    public static boolean isNotEmpty(Map<?, ?> map) {
        return !isEmpty(map);
    }

    /**
     * 리스트를 지정된 크기로 분할
     */
    public static <T> List<List<T>> partition(List<T> list, int size) {
        if (isEmpty(list) || size <= 0) {
            return Collections.emptyList();
        }

        return IntStream.range(0, (list.size() + size - 1) / size)
                       .mapToObj(i -> list.subList(i * size, Math.min((i + 1) * size, list.size())))
                       .collect(Collectors.toList());
    }

    /**
     * 두 리스트의 교집합 반환
     */
    public static <T> List<T> intersection(List<T> list1, List<T> list2) {
        if (isEmpty(list1) || isEmpty(list2)) {
            return Collections.emptyList();
        }

        return list1.stream()
                   .filter(list2::contains)
                   .distinct()
                   .collect(Collectors.toList());
    }

    /**
     * 두 리스트의 차집합 반환 (list1 - list2)
     */
    public static <T> List<T> difference(List<T> list1, List<T> list2) {
        if (isEmpty(list1)) {
            return Collections.emptyList();
        }
        if (isEmpty(list2)) {
            return new ArrayList<>(list1);
        }

        return list1.stream()
                   .filter(item -> !list2.contains(item))
                   .collect(Collectors.toList());
    }

    /**
     * 리스트에서 null 값 제거
     */
    public static <T> List<T> removeNulls(List<T> list) {
        if (isEmpty(list)) {
            return Collections.emptyList();
        }

        return list.stream()
                  .filter(Objects::nonNull)
                  .collect(Collectors.toList());
    }

    /**
     * 리스트를 Map으로 변환 (중복 키 처리)
     */
    public static <T, K> Map<K, T> toMap(List<T> list, Function<T, K> keyExtractor) {
        if (isEmpty(list)) {
            return Collections.emptyMap();
        }

        return list.stream()
                  .filter(Objects::nonNull)
                  .collect(Collectors.toMap(
                      keyExtractor,
                      Function.identity(),
                      (existing, replacement) -> replacement,
                      LinkedHashMap::new
                  ));
    }

    /**
     * 리스트를 Map으로 그룹화
     */
    public static <T, K> Map<K, List<T>> groupBy(List<T> list, Function<T, K> keyExtractor) {
        if (isEmpty(list)) {
            return Collections.emptyMap();
        }

        return list.stream()
                  .filter(Objects::nonNull)
                  .collect(Collectors.groupingBy(keyExtractor, LinkedHashMap::new, Collectors.toList()));
    }
}
```

## 사용 가이드

### 유틸리티 클래스 설계 원칙

1. **final class**: 상속 불가능하도록 설정
2. **private constructor**: 인스턴스화 방지
3. **static methods**: 모든 메서드를 정적 메서드로 구현
4. **null safety**: null 값에 대한 안전한 처리
5. **exception handling**: 적절한 예외 처리 및 로깅
6. **immutability**: 가능한 한 불변 객체 사용

### 로깅 가이드

```java
// 유틸리티 메서드에서 로깅 예시
@Slf4j
public final class SomeUtil {
    
    public static String processData(String input) {
        log.debug("데이터 처리 시작: {}", input);
        
        try {
            String result = doProcess(input);
            log.debug("데이터 처리 완료: {} -> {}", input, result);
            return result;
        } catch (Exception e) {
            log.error("데이터 처리 중 오류 발생: input={}, error={}", input, e.getMessage());
            throw new ProcessingException("데이터 처리에 실패했습니다", e);
        }
    }
}
```

### 테스트 작성 권장사항

```java
@ExtendWith(MockitoExtension.class)
class StringUtilTest {

    @Test
    void testMaskEmail() {
        // given
        String email = "test@example.com";
        
        // when
        String maskedEmail = StringUtil.maskEmail(email);
        
        // then
        assertThat(maskedEmail).isEqualTo("t**t@example.com");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "  ", "invalid"})
    void testIsEmpty(String input) {
        // when & then
        assertThat(StringUtil.isEmpty(input)).isTrue();
    }
}
```

## Best Practices

1. **성능 고려**: 자주 사용되는 유틸리티는 성능 최적화 필요
2. **보안 고려**: 민감한 데이터 처리 시 보안 규정 준수
3. **재사용성**: 프로젝트 전반에서 재사용 가능하도록 범용적으로 설계
4. **문서화**: 복잡한 로직은 JavaDoc으로 상세 설명
5. **단위 테스트**: 모든 유틸리티 메서드에 대한 단위 테스트 작성
6. **버전 관리**: API 변경 시 하위 호환성 고려

이러한 유틸리티 클래스들을 활용하여 코드의 재사용성을 높이고 일관된 처리 방식을 유지할 수 있습니다.