# JWT Token 鉴权审计

## 目录

- [框架识别](#框架识别)
- [JWT 结构分析](#jwt-结构分析)
- [实现审计](#实现审计)
- [常见漏洞模式](#常见漏洞模式)
- [审计检查清单](#审计检查清单)

---

## 框架识别

### 识别特征

| 特征类型 | 特征内容 |
|----------|----------|
| Maven 依赖 | `io.jsonwebtoken:jjwt`, `com.auth0:java-jwt`, `nimbus-jose-jwt` |
| 请求头 | `Authorization: Bearer <token>` |
| 核心类 | `Jwts`, `JwtParser`, `Claims` |

### 常用 JWT 库

```xml
<!-- jjwt (最常用) -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>

<!-- java-jwt (Auth0) -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.18.0</version>
</dependency>
```

---

## JWT 结构分析

### JWT 组成

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.    # Header
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikp.  # Payload
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  # Signature
```

### Header 检查

```json
{
  "alg": "HS256",  // 算法 - 检查是否为 none
  "typ": "JWT"
}
```

### Payload 检查

```json
{
  "sub": "1234567890",     // 主题 (用户ID)
  "name": "John Doe",      // 自定义声明
  "role": "admin",         // ⚠️ 权限信息
  "iat": 1516239022,       // 签发时间
  "exp": 1516242622,       // 过期时间
  "nbf": 1516239022        // 生效时间
}
```

---

## 实现审计

### Token 生成审计

```java
public class JwtUtil {
    
    // ⚠️ 检查点 1: 密钥管理
    private static final String SECRET_KEY = "mySecretKey123";  // 硬编码密钥!
    
    // ⚠️ 检查点 2: 密钥强度
    // 密钥太短，容易被暴力破解
    
    public String generateToken(User user) {
        return Jwts.builder()
            .setSubject(user.getUsername())
            
            // ⚠️ 检查点 3: 过期时间
            .setExpiration(new Date(System.currentTimeMillis() + 86400000 * 30))  // 30天太长
            
            // ⚠️ 检查点 4: 敏感信息
            .claim("password", user.getPassword())  // 不应包含密码!
            .claim("role", user.getRole())
            
            // ⚠️ 检查点 5: 算法选择
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
            
            .compact();
    }
}
```

### Token 验证审计

```java
public class JwtFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) {
        
        String authHeader = request.getHeader("Authorization");
        
        // ⚠️ 检查点 1: Token 提取
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);  // 无 Token 直接放行?
            return;
        }
        
        String token = authHeader.substring(7);
        
        try {
            // ⚠️ 检查点 2: Token 解析
            Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
            
            // ⚠️ 检查点 3: 是否验证过期时间
            // jjwt 默认验证 exp，但需确认
            
            // ⚠️ 检查点 4: 用户信息处理
            String username = claims.getSubject();
            String role = claims.get("role", String.class);
            
            // ⚠️ 检查点 5: 是否验证用户仍然有效
            // 用户可能已被禁用/删除
            
            // 设置认证信息
            UsernamePasswordAuthenticationToken auth = 
                new UsernamePasswordAuthenticationToken(username, null, 
                    Collections.singletonList(new SimpleGrantedAuthority(role)));
            SecurityContextHolder.getContext().setAuthentication(auth);
            
        } catch (Exception e) {
            // ⚠️ 检查点 6: 异常处理
            response.setStatus(401);
            return;
        }
        
        chain.doFilter(request, response);
    }
}
```

### Refresh Token 审计

```java
public class TokenService {
    
    // ⚠️ 检查点: Refresh Token 机制
    public TokenPair refreshToken(String refreshToken) {
        // 1. 验证 refresh token
        // 2. 检查是否在黑名单中
        // 3. 生成新的 access token
        // 4. 可选: 轮换 refresh token
    }
}
```

---

## 常见漏洞模式

### 1. Algorithm None 攻击

```java
// ⚠️ 漏洞: 未验证算法
Claims claims = Jwts.parser()
    .setSigningKey(SECRET_KEY)
    .parseClaimsJws(token)
    .getBody();

// 攻击者可以将 header 改为 {"alg": "none"}
// 并移除签名部分，绕过签名验证
```

**检测方法：**
```python
# 构造 none 算法的 token
header = base64url({"alg": "none", "typ": "JWT"})
payload = base64url({"sub": "admin", "role": "admin"})
malicious_token = f"{header}.{payload}."
```

### 2. 密钥弱强度

```java
// ⚠️ 弱密钥
private static final String SECRET = "secret";  // 太短
private static final String SECRET = "123456";  // 常见密码

// ✅ 强密钥
private static final String SECRET = "aVeryLongAndRandomSecretKeyThatIsAtLeast256BitsLong!@#$%";
```

**暴力破解工具：**
- jwt_tool
- hashcat

### 3. 密钥硬编码

```java
// ⚠️ 硬编码密钥
private static final String SECRET_KEY = "mySecretKey123";

// ✅ 从环境变量读取
@Value("${jwt.secret}")
private String secretKey;
```

### 4. 过期时间过长

```java
// ⚠️ 过期时间 30 天
.setExpiration(new Date(System.currentTimeMillis() + 86400000L * 30))

// ✅ Access Token 15 分钟，Refresh Token 7 天
.setExpiration(new Date(System.currentTimeMillis() + 900000))  // 15 min
```

### 5. 敏感信息泄露

```java
// ⚠️ Token 中包含敏感信息
.claim("password", user.getPassword())
.claim("email", user.getEmail())
.claim("phone", user.getPhone())

// JWT payload 是 base64 编码，可被解码
```

### 6. 无 Token 吊销机制

```java
// ⚠️ 无法使已签发的 Token 失效
// 用户修改密码、被禁用后，旧 Token 仍然有效

// ✅ 实现 Token 黑名单
public boolean isTokenBlacklisted(String token) {
    return blacklistRepository.existsByToken(token);
}
```

### 7. 未验证用户状态

```java
// ⚠️ 仅验证 Token，未验证用户状态
Claims claims = parseToken(token);
String userId = claims.getSubject();
// 直接使用 userId，未检查用户是否仍然有效

// ✅ 验证用户状态
User user = userService.findById(userId);
if (user == null || user.isDisabled()) {
    throw new AuthenticationException("User invalid");
}
```

### 8. Algorithm Confusion 攻击

```java
// ⚠️ RS256 到 HS256 的算法混淆
// 如果系统使用 RS256，攻击者可以：
// 1. 获取公钥
// 2. 将算法改为 HS256
// 3. 用公钥作为 HS256 的密钥签名
```

---

## 审计检查清单

### 密钥安全

- [ ] 密钥是否硬编码
- [ ] 密钥强度是否足够 (>= 256 bits)
- [ ] 密钥是否定期轮换
- [ ] 密钥是否安全存储

### Token 生成

- [ ] 过期时间是否合理 (Access Token <= 15min)
- [ ] 是否包含敏感信息
- [ ] 算法选择是否安全 (推荐 RS256)

### Token 验证

- [ ] 是否验证签名
- [ ] 是否验证过期时间
- [ ] 是否验证算法 (防止 none 攻击)
- [ ] 是否验证用户状态

### Token 管理

- [ ] 是否有 Token 吊销机制
- [ ] 是否有 Refresh Token 机制
- [ ] Refresh Token 是否安全存储

---

## 输出示例

```markdown
=== [JWT-001] 密钥硬编码 ===
风险等级: 高
位置: JwtUtil.java:15

问题描述:
- JWT 签名密钥硬编码在源码中
- 密钥: "mySecretKey123"
- 攻击者获取源码后可伪造任意 Token

建议修复:
- 从环境变量或配置中心读取密钥
- 使用足够强度的随机密钥

---

=== [JWT-002] 过期时间过长 ===
风险等级: 中
位置: JwtUtil.java:28

问题描述:
- Access Token 过期时间为 30 天
- Token 泄露后风险窗口过大

当前配置:
.setExpiration(new Date(System.currentTimeMillis() + 86400000L * 30))

建议修复:
- Access Token 过期时间设为 15-30 分钟
- 使用 Refresh Token 机制续期

---

=== [JWT-003] 无 Token 吊销机制 ===
风险等级: 中
位置: JwtFilter.java

问题描述:
- 系统无法使已签发的 Token 失效
- 用户修改密码、被禁用后旧 Token 仍有效

建议修复:
- 实现 Token 黑名单机制
- 或在 Token 中包含密码版本号，密码修改后旧 Token 失效
```
