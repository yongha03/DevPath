package com.devpath.domain.job.repository;

import com.devpath.domain.job.entity.JobPosting;
import com.devpath.domain.job.entity.JobPostingStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JobPostingRepository extends JpaRepository<JobPosting, Long> {

  boolean existsByExternalJobIdAndIsDeletedFalse(String externalJobId);

  @EntityGraph(attributePaths = "company")
  List<JobPosting> findAllByStatusAndIsDeletedFalseOrderByCreatedAtDesc(JobPostingStatus status);

  @EntityGraph(attributePaths = "company")
  List<JobPosting> findAllByIsDeletedFalseOrderByCreatedAtDesc();

  @EntityGraph(attributePaths = "company")
  Optional<JobPosting> findByIdAndIsDeletedFalse(Long id);
}
