# SecureBankApp Application Documentation
This course provides a comprehensive exploration of Spring Security Architecture. Gain insights into crucial packages, interfaces, and classes that play pivotal roles in handling authentication and authorization requests within web applications. The course delves into essential security concepts, including CORs, CSRF, JWT, OAUTH2, password management, method-level security, as well as the effective management of users, roles, and authorities within web applications. By the end of this course, you'll master the intricacies of Spring Security and be well-equipped to implement robust security measures in your projects.

## 01 - Getting Started: 
***Project name: 1-spring-security-basic***
1. Add Spring Security Dependency: Include the Spring Security dependency in your project's configuration.
    ```
        <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
    ```
2. Configure Basic User Credentials:
Utilize [Security Properties](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#appendix.application-properties.security) to manage basic username and password authentication.
Example application.properties:
```shell
spring.security.user.name=user
spring.security.user.password=secret
```
Customize the provided credentials to suit your application's security requirements.