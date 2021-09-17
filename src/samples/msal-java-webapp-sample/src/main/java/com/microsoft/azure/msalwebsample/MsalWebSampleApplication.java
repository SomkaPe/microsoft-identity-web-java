// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample;

import com.microsoft.azure.webappauth.AuthHelper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@ServletComponentScan
@SpringBootApplication
public class MsalWebSampleApplication extends SpringBootServletInitializer {
	private String AAD_CONFIG_FILE = "aad_auth_config.json";

	@Bean
	public AuthHelper authHelperBean() throws IOException {
		File file = new File(getClass().getClassLoader().getResource(AAD_CONFIG_FILE).getFile());

		String jsonStr = new String(Files.readAllBytes(file.toPath()));

		return new AuthHelper(jsonStr);
	}

	public static void main(String[] args) {
		SpringApplication.run(MsalWebSampleApplication.class, args);
	}
}
