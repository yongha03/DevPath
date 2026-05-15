package com.devpath.api.job.service;

import com.devpath.api.job.dto.JobkoreaJobRequest;
import com.devpath.api.job.dto.JobkoreaJobResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JobkoreaJobService {

  private final JobkoreaApiClient jobkoreaApiClient;

  public JobkoreaJobResponse.SearchResult search(JobkoreaJobRequest.Search request) {
    return jobkoreaApiClient.search(request);
  }
}
