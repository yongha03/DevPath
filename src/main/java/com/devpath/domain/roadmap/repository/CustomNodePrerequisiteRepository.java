package com.devpath.domain.roadmap.repository;

import com.devpath.domain.roadmap.entity.CustomNodePrerequisite;
import com.devpath.domain.roadmap.entity.CustomRoadmap;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CustomNodePrerequisiteRepository extends JpaRepository<CustomNodePrerequisite, Long> {
    List<CustomNodePrerequisite> findAllByCustomRoadmap(CustomRoadmap customRoadmap);

    void deleteAllByCustomRoadmap(CustomRoadmap customRoadmap);
}
