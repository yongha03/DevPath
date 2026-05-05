package com.devpath.api.job.service;

import com.devpath.api.job.dto.CompanyRequest;
import com.devpath.api.job.dto.CompanyResponse;
import com.devpath.api.job.dto.JobPostingRequest;
import com.devpath.api.job.dto.JobPostingResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.job.entity.Company;
import com.devpath.domain.job.entity.JobPosting;
import com.devpath.domain.job.entity.JobPostingStatus;
import com.devpath.domain.job.repository.CompanyRepository;
import com.devpath.domain.job.repository.JobPostingRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JobAdminService {

  private final CompanyRepository companyRepository;
  private final JobPostingRepository jobPostingRepository;

  @Transactional
  public CompanyResponse.Detail createCompany(CompanyRequest.Create request) {
    validateCompanyNameNotDuplicated(request.name());

    Company company =
        Company.builder()
            .name(request.name())
            .description(request.description())
            .websiteUrl(request.websiteUrl())
            .logoUrl(request.logoUrl())
            .industry(request.industry())
            .location(request.location())
            .build();

    return CompanyResponse.Detail.from(companyRepository.save(company));
  }

  public List<CompanyResponse.Summary> getCompanies() {
    return companyRepository.findAllByIsDeletedFalseOrderByCreatedAtDesc().stream()
        .map(CompanyResponse.Summary::from)
        .toList();
  }

  public CompanyResponse.Detail getCompany(Long companyId) {
    return CompanyResponse.Detail.from(getActiveCompany(companyId));
  }

  @Transactional
  public CompanyResponse.Detail updateCompany(Long companyId, CompanyRequest.Update request) {
    Company company = getActiveCompany(companyId);

    if (!company.getName().equals(request.name())) {
      validateCompanyNameNotDuplicated(request.name());
    }

    company.updateProfile(
        request.name(),
        request.description(),
        request.websiteUrl(),
        request.logoUrl(),
        request.industry(),
        request.location());

    return CompanyResponse.Detail.from(company);
  }

  @Transactional
  public CompanyResponse.Detail verifyCompany(Long companyId, CompanyRequest.Verify request) {
    Company company = getActiveCompany(companyId);

    company.changeVerificationStatus(request.status(), request.memo());

    return CompanyResponse.Detail.from(company);
  }

  @Transactional
  public JobPostingResponse.Detail createJob(JobPostingRequest.Create request) {
    Company company = getActiveCompany(request.companyId());

    validateExternalJobIdNotDuplicated(request.externalJobId());

    JobPosting jobPosting =
        JobPosting.builder()
            .company(company)
            .title(request.title())
            .jobRole(request.jobRole())
            .description(request.description())
            .requiredSkills(request.requiredSkills())
            .region(request.region())
            .careerLevel(request.careerLevel())
            .sourceUrl(request.sourceUrl())
            .source(request.source())
            .status(request.status())
            .deadline(request.deadline())
            .externalJobId(request.externalJobId())
            .build();

    return JobPostingResponse.Detail.from(jobPostingRepository.save(jobPosting));
  }

  public List<JobPostingResponse.Summary> getOpenJobs() {
    return jobPostingRepository
        .findAllByStatusAndIsDeletedFalseOrderByCreatedAtDesc(JobPostingStatus.OPEN)
        .stream()
        .map(JobPostingResponse.Summary::from)
        .toList();
  }

  public JobPostingResponse.Detail getJob(Long jobId) {
    return JobPostingResponse.Detail.from(getActiveJob(jobId));
  }

  @Transactional
  public JobPostingResponse.Detail updateJob(Long jobId, JobPostingRequest.Update request) {
    JobPosting jobPosting = getActiveJob(jobId);

    if (isExternalJobIdChanged(jobPosting.getExternalJobId(), request.externalJobId())) {
      validateExternalJobIdNotDuplicated(request.externalJobId());
    }

    jobPosting.update(
        request.title(),
        request.jobRole(),
        request.description(),
        request.requiredSkills(),
        request.region(),
        request.careerLevel(),
        request.sourceUrl(),
        request.source(),
        request.status(),
        request.deadline(),
        request.externalJobId());

    return JobPostingResponse.Detail.from(jobPosting);
  }

  public JobPostingResponse.CollectResult collectJobs(JobPostingRequest.Collect request) {
    return JobPostingResponse.CollectResult.completed(
        request.source(), request.keyword(), request.limit());
  }

  private Company getActiveCompany(Long companyId) {
    return companyRepository
        .findByIdAndIsDeletedFalse(companyId)
        .orElseThrow(() -> new CustomException(ErrorCode.JOB_COMPANY_NOT_FOUND));
  }

  private JobPosting getActiveJob(Long jobId) {
    return jobPostingRepository
        .findByIdAndIsDeletedFalse(jobId)
        .orElseThrow(() -> new CustomException(ErrorCode.JOB_POSTING_NOT_FOUND));
  }

  private void validateCompanyNameNotDuplicated(String name) {
    if (companyRepository.existsByNameAndIsDeletedFalse(name)) {
      throw new CustomException(ErrorCode.JOB_COMPANY_ALREADY_EXISTS);
    }
  }

  private void validateExternalJobIdNotDuplicated(String externalJobId) {
    if (externalJobId == null || externalJobId.trim().isEmpty()) {
      return;
    }

    if (jobPostingRepository.existsByExternalJobIdAndIsDeletedFalse(externalJobId)) {
      throw new CustomException(ErrorCode.JOB_POSTING_ALREADY_EXISTS);
    }
  }

  private boolean isExternalJobIdChanged(
      String currentExternalJobId, String requestedExternalJobId) {
    if (currentExternalJobId == null) {
      return requestedExternalJobId != null;
    }

    return !currentExternalJobId.equals(requestedExternalJobId);
  }
}
