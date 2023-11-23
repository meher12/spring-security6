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

## 02 - Changing the Default Security Configurations:
***Project name: 2-spring-security-configurations***
we've taken the initiative to enhance the default security configuration by customizing the defaultSecurityFilterChain method inside ProjectSecurityConfig class:
1. Securing Specific Services:
   The ***.antMatchers("/secured-service1", "/secured-service2").authenticated()*** configuration ensures that access to "/secured-service1" and "/secured-service2" requires authentication. Users must be authenticated to access these services.
2. Allowing Unrestricted Access:
   Conversely, ***.antMatchers("/public-service1", "/public-service2").permitAll()*** allows unrestricted access to "/public-service1" and "/public-service2". These services are accessible without authentication.
3. Denying Access to Restricted Endpoints:
   The new configuration ***.antMatchers("/restricted-service1", "/restricted-service2").denyAll()*** explicitly denies access to "/restricted-service1" and "/restricted-service2". Any attempt to access these endpoints will be rejected.
4. Default Authentication for Other Endpoints:
   The configuration ***.anyRequest().authenticated()*** ensures that any other request not covered by specific matchers requires authentication.
5. Permitting or Denying Access to All Other Endpoints:
   ***.anyRequest().permitAll()*** permits access to all other endpoints, providing an open access policy. Alternatively, ***.anyRequest().denyAll()*** denies access to all other endpoints, creating a restrictive access policy.
6. HTTP Basic Authentication:
   Finally, ***.httpBasic()*** configures the application to use HTTP Basic Authentication.