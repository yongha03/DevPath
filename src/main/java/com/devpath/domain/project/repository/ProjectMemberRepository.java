package com.devpath.domain.project.repository;

import com.devpath.domain.project.entity.ProjectMember;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectMemberRepository extends JpaRepository<ProjectMember, Long> {

    boolean existsByProjectIdAndLearnerId(Long projectId, Long learnerId);

    List<ProjectMember> findAllByLearnerIdOrderByJoinedAtDesc(Long learnerId);
}
