# 鉴权组件版本漏洞库

## 目录

- [版本识别方法](#版本识别方法)
- [Shiro 漏洞](#shiro-漏洞)
- [Spring Security 漏洞](#spring-security-漏洞)
- [JWT 相关漏洞](#jwt-相关漏洞)
- [其他鉴权组件漏洞](#其他鉴权组件漏洞)
- [版本检测脚本](#版本检测脚本)

---

## 版本识别方法

### 方法 1: JAR 文件名扫描

```bash
# 扫描 lib 目录
find . -name "*.jar" | xargs -I {} basename {} | grep -iE "shiro|security|jwt|pac4j|cas"

# 常见文件名格式
shiro-core-1.4.0.jar
shiro-spring-1.4.0.jar
shiro-web-1.4.0.jar
spring-security-core-5.7.3.jar
spring-security-web-5.7.3.jar
jjwt-0.9.1.jar
jjwt-api-0.11.2.jar
java-jwt-3.18.0.jar
pac4j-core-4.0.0.jar
```

### 方法 2: pom.xml 解析

```bash
# 搜索 pom.xml 中的版本定义
grep -A2 -B2 "shiro\|spring-security\|jjwt\|java-jwt\|pac4j" pom.xml
```

```xml
<!-- Shiro -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.4.0</version>
</dependency>

<!-- Spring Security -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-core</artifactId>
    <version>5.7.3</version>
</dependency>

<!-- JJWT -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

### 方法 3: MANIFEST.MF 解析

```bash
# 解压 JAR 查看版本信息
unzip -p shiro-core-*.jar META-INF/MANIFEST.MF | grep -i version

# 输出示例
Implementation-Version: 1.4.0
Bundle-Version: 1.4.0.RELEASE
```

### 方法 4: Maven pom.properties

```bash
# JAR 内的 Maven 元数据
unzip -p shiro-core.jar META-INF/maven/org.apache.shiro/shiro-core/pom.properties

# 输出示例
version=1.4.0
groupId=org.apache.shiro
artifactId=shiro-core
```

### 方法 5: Gradle 依赖

```groovy
// build.gradle
implementation 'org.apache.shiro:shiro-spring:1.4.0'
implementation 'org.springframework.security:spring-security-core:5.7.3'
```

---

## Shiro 漏洞

### CVE-2023-22602 (< 1.11.0)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.11.0 |
| 风险等级 | 高 |
| 类型 | 路径绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- 当 Shiro 与 Spring Boot 2.6+ 配合使用时
- 路径匹配行为变化导致绕过

**验证 PoC：**
```http
GET /admin/. HTTP/1.1
Host: {{host}}
```

---

### CVE-2022-32532 (< 1.9.1)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.9.1 |
| 风险等级 | 高 |
| 类型 | RegexRequestMatcher 绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- RegexRequestMatcher 使用 `.` 匹配时存在缺陷
- 正则中 `.` 默认不匹配换行符，可通过换行符绕过

**验证 PoC：**
```http
GET /admin%0a HTTP/1.1
Host: {{host}}
```

---

### CVE-2021-41303 (< 1.8.0)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.8.0 |
| 风险等级 | 高 |
| 类型 | 路径绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- 路径标准化处理不当
- 可通过特殊字符绕过鉴权

**验证 PoC：**
```http
GET /admin/%2e HTTP/1.1
Host: {{host}}

GET /admin/%2e%2e HTTP/1.1
Host: {{host}}
```

---

### CVE-2020-17523 (< 1.7.1)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.7.1 |
| 风险等级 | 高 |
| 类型 | 认证绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- SpringBeanTypeConverter 类型转换缺陷
- 攻击者可利用空白字符操纵 classname 值绕过认证
- **注意：此漏洞需要 Shiro + Spring 集成环境**

**利用前提：**
- 必须在 Shiro 与 Spring 集成环境下使用

---

### CVE-2020-13933 (< 1.6.0)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.6.0 |
| 风险等级 | 高 |
| 类型 | 认证绕过 |
| CVSS | 7.5 |

**漏洞描述：**
- 分号可绕过路径匹配
- Ant 风格路径匹配缺陷

**验证 PoC：**
```http
GET /admin/;page HTTP/1.1
Host: {{host}}

GET /;/admin/page HTTP/1.1
Host: {{host}}
```

---

### CVE-2020-11989 (< 1.5.3)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.5.3 |
| 风险等级 | 高 |
| 类型 | 路径绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- Spring 框架下路径匹配绕过
- URL 编码斜杠可绕过

**验证 PoC：**
```http
GET /admin/page%2f HTTP/1.1
Host: {{host}}

GET /admin/page%2F HTTP/1.1
Host: {{host}}
```

---

### CVE-2020-1957 (< 1.5.2)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 1.5.2 |
| 风险等级 | 高 |
| 类型 | 路径绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- Spring 动态控制器路径绕过

**验证 PoC：**
```http
GET /xxx/..;/admin/ HTTP/1.1
Host: {{host}}
```

---

### CVE-2016-4437 (RememberMe 反序列化)

| 属性 | 值 |
|------|-----|
| 影响版本 | 使用默认密钥的所有版本 |
| 风险等级 | 严重 |
| 类型 | 反序列化 RCE |
| CVSS | 9.8 |

**漏洞描述：**
- RememberMe Cookie 使用 AES 加密
- 默认密钥: `kPH+bIxk5D2deZiIxcaaaA==`
- 可构造恶意序列化数据执行命令

**检测方法：**
```java
// 检查是否使用默认密钥
// 搜索以下代码
CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
rememberMeManager.setCipherKey(Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));
```

**常见硬编码密钥：**
```
kPH+bIxk5D2deZiIxcaaaA==
2AvVhdsgUs0FSA3SDFAdag==
3AvVhmFLUs0KTA3Kprsdag==
4AvVhmFLUs0KTA3Kprsdag==
Z3VucwAAAAAAAAAAAAAAAA==
wGiHplamyXlVB11UXWol8g==
```

---

## Spring Security 漏洞

### CVE-2024-22234 (< 6.1.7 / < 6.2.2)

| 属性 | 值 |
|------|-----|
| 影响版本 | 6.1.0-6.1.6, 6.2.0-6.2.1 |
| 风险等级 | 高 |
| 类型 | 授权绕过 |

**漏洞描述：**
- AuthorizationFilter 处理问题

---

### CVE-2022-31692 (< 5.7.5 / < 5.6.9)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 5.7.5, < 5.6.9 |
| 风险等级 | 高 |
| 类型 | 授权绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- forward/include 请求授权绕过

---

### CVE-2022-22978 (< 5.4.11 / < 5.5.7 / < 5.6.4)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 5.4.11, < 5.5.7, < 5.6.4 |
| 风险等级 | 高 |
| 类型 | RegEx DoS / 授权绕过 |
| CVSS | 9.8 |

**漏洞描述：**
- RegexRequestMatcher 正则表达式处理问题
- 正则中 `.` 默认不匹配换行符
- 可通过 `%0a` 或 `%0d` 绕过授权

**验证 PoC：**
```http
GET /admin%0d%0a HTTP/1.1
Host: {{host}}
```

---

### CVE-2022-22976 (< 5.6.4 / < 5.5.7)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 5.6.4, < 5.5.7 |
| 风险等级 | 中 |
| 类型 | BCrypt 密码编码器整数溢出 |

---

### CVE-2021-22119 (< 5.5.1 / < 5.4.7)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 5.5.1, < 5.4.7 |
| 风险等级 | 高 |
| 类型 | DoS |

---

### CVE-2018-1199 (< 5.0.1 / < 4.2.4)

| 属性 | 值 |
|------|-----|
| 影响版本 | < 5.0.1, < 4.2.4 |
| 风险等级 | 中 |
| 类型 | 路径绕过 |

**漏洞描述：**
- 路径参数（分号后内容）未正确处理

---

## JWT 相关漏洞

### JJWT 安全建议

| 版本范围 | 风险 | 说明 |
|----------|------|------|
| < 0.10.0 | 中 | 旧 API，签名验证可能存在问题 |
| < 0.11.0 | 低 | 建议升级到最新 API |
| >= 0.12.0 | 安全 | 推荐使用 |

### java-jwt (Auth0)

| 版本范围 | 风险 | 说明 |
|----------|------|------|
| < 3.19.0 | 中 | 安全增强 |
| >= 4.0.0 | 安全 | 推荐使用 |

### 通用 JWT 漏洞

**Algorithm None 攻击：**
- 修改 header 的 alg 为 none
- 移除签名部分

**Algorithm Confusion：**
- RS256 改为 HS256
- 使用公钥作为 HMAC 密钥

**弱密钥：**
- 密钥可被暴力破解
- 使用常见密码

---

## 其他鉴权组件漏洞

### PAC4J

| CVE | 影响版本 | 风险 | 描述 |
|-----|----------|------|------|
| CVE-2021-44878 | < 4.0.0 | 高 | 认证绕过 |
| CVE-2023-25581 | < 5.7.0 | 高 | OIDC 认证绕过 |

### CAS (Central Authentication Service)

| CVE | 影响版本 | 风险 | 描述 |
|-----|----------|------|------|
| CVE-2021-42567 | < 6.4.2 | 高 | 认证绕过 |
| CVE-2022-30295 | < 6.5.0 | 中 | 信息泄露 |

### Keycloak

| CVE | 影响版本 | 风险 | 描述 |
|-----|----------|------|------|
| CVE-2023-6134 | < 23.0.3 | 高 | 认证绕过 |
| CVE-2023-6563 | < 23.0.3 | 高 | 权限提升 |

---

## 版本检测脚本

### Bash 脚本

```bash
#!/bin/bash
# auth_version_check.sh - 鉴权组件版本检测

LIB_DIR=${1:-"WEB-INF/lib"}

echo "=== 鉴权组件版本检测 ==="
echo "扫描目录: $LIB_DIR"
echo ""

# Shiro
echo "--- Apache Shiro ---"
ls "$LIB_DIR" 2>/dev/null | grep -i "shiro" | while read jar; do
    version=$(echo "$jar" | grep -oP '\d+\.\d+\.\d+')
    echo "  $jar"
    if [[ "$version" < "1.11.0" ]]; then
        echo "    ⚠️ 警告: 版本 $version 存在已知漏洞"
    fi
done

# Spring Security
echo ""
echo "--- Spring Security ---"
ls "$LIB_DIR" 2>/dev/null | grep -i "spring-security" | while read jar; do
    version=$(echo "$jar" | grep -oP '\d+\.\d+\.\d+')
    echo "  $jar"
    if [[ "$version" < "5.7.5" ]]; then
        echo "    ⚠️ 警告: 版本 $version 可能存在漏洞"
    fi
done

# JWT
echo ""
echo "--- JWT 相关 ---"
ls "$LIB_DIR" 2>/dev/null | grep -iE "jwt|jose" | while read jar; do
    echo "  $jar"
done

# PAC4J
echo ""
echo "--- PAC4J ---"
ls "$LIB_DIR" 2>/dev/null | grep -i "pac4j" | while read jar; do
    version=$(echo "$jar" | grep -oP '\d+\.\d+\.\d+')
    echo "  $jar"
    if [[ "$version" < "4.0.0" ]]; then
        echo "    ⚠️ 警告: 版本 $version 存在已知漏洞"
    fi
done
```

### Python 脚本

```python
#!/usr/bin/env python3
"""鉴权组件版本检测"""

import os
import re
import zipfile
from pathlib import Path

# 漏洞版本数据库
VULN_DB = {
    "shiro": [
        {"version": "1.11.0", "cves": ["CVE-2023-22602"]},
        {"version": "1.10.0", "cves": ["CVE-2022-32532"]},
        {"version": "1.7.1", "cves": ["CVE-2021-41303"]},
        {"version": "1.6.0", "cves": ["CVE-2020-13933"]},
        {"version": "1.5.3", "cves": ["CVE-2020-11989"]},
    ],
    "spring-security": [
        {"version": "5.7.5", "cves": ["CVE-2022-31692"]},
        {"version": "5.6.4", "cves": ["CVE-2022-22978"]},
    ],
    "pac4j": [
        {"version": "4.0.0", "cves": ["CVE-2021-44878"]},
    ],
}

def parse_version(version_str):
    """解析版本号"""
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(map(int, match.groups()))
    return None

def check_vulnerability(component, version):
    """检查组件是否存在漏洞"""
    if component not in VULN_DB:
        return []
    
    vulns = []
    current = parse_version(version)
    if not current:
        return []
    
    for vuln in VULN_DB[component]:
        safe_version = parse_version(vuln["version"])
        if current < safe_version:
            vulns.extend(vuln["cves"])
    
    return vulns

def scan_lib_directory(lib_path):
    """扫描 lib 目录"""
    results = []
    
    for jar in Path(lib_path).glob("*.jar"):
        name = jar.name.lower()
        
        # 检测组件类型
        component = None
        if "shiro" in name:
            component = "shiro"
        elif "spring-security" in name:
            component = "spring-security"
        elif "pac4j" in name:
            component = "pac4j"
        elif "jwt" in name or "jose" in name:
            component = "jwt"
        
        if component:
            version_match = re.search(r'(\d+\.\d+\.\d+)', name)
            version = version_match.group(1) if version_match else "unknown"
            vulns = check_vulnerability(component, version) if version != "unknown" else []
            
            results.append({
                "file": jar.name,
                "component": component,
                "version": version,
                "vulnerabilities": vulns,
            })
    
    return results

if __name__ == "__main__":
    import sys
    lib_path = sys.argv[1] if len(sys.argv) > 1 else "WEB-INF/lib"
    
    print("=== 鉴权组件版本检测 ===\n")
    
    results = scan_lib_directory(lib_path)
    
    for r in results:
        status = "❌ 存在漏洞" if r["vulnerabilities"] else "✅ 安全"
        print(f"{r['file']}")
        print(f"  组件: {r['component']}")
        print(f"  版本: {r['version']}")
        print(f"  状态: {status}")
        if r["vulnerabilities"]:
            print(f"  CVE: {', '.join(r['vulnerabilities'])}")
        print()
```

---

## 输出模板

```markdown
## 组件版本安全分析

### 检测结果汇总

| 组件 | 版本 | 状态 | CVE |
|------|------|------|-----|
| shiro-core | 1.4.0 | ❌ 高危 | CVE-2020-11989, CVE-2020-13933 |
| spring-security-core | 5.7.3 | ⚠️ 需升级 | CVE-2022-31692 |
| jjwt | 0.11.2 | ✅ 安全 | - |

### 高危漏洞详情

=== [VERSION-001] Shiro 版本存在多个已知漏洞 ===
组件: shiro-core-1.4.0.jar
当前版本: 1.4.0
安全版本: >= 1.11.0
风险等级: 高

存在漏洞:
- CVE-2020-11989: 路径绕过 (CVSS: 9.8)
- CVE-2020-13933: 认证绕过 (CVSS: 7.5)
- CVE-2020-17523: 路径绕过 (CVSS: 9.8)
- CVE-2021-41303: 路径绕过 (CVSS: 9.8)
- CVE-2022-32532: RegEx 绕过 (CVSS: 9.8)

修复建议:
- 立即升级到 Shiro 1.13.0 或更高版本
- 临时缓解: 检查并加固 URL 过滤规则
```
