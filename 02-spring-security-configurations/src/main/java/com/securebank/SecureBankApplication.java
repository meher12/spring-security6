package com.securebank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({"com.securebank.controller", "com.securebank.config"}) //Optional
public class SecureBankApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureBankApplication.class, args);
	}

}
