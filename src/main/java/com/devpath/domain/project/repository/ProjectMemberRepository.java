package com.devpath.domain.project.repository;
import com.devpath.domain.project.entity.ProjectMember;
import org.springframework.data.jpa.repository.JpaRepository;
public interface ProjectMemberRepository extends JpaRepository<ProjectMember, Long> {}