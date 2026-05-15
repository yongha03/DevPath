package com.devpath.common.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jobkorea.api")
@Getter
@Setter
public class JobkoreaProperties {

  private String jobListUrl;
  private String starterListUrl;
  private String apiKey;
  private String apiParamName = "api";
  private String oemCode = "C900";
}
