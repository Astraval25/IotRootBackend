package com.astraval.iotrootbackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class IotrootbackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(IotrootbackendApplication.class, args);
	}

}
