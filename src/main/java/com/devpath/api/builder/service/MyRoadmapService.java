package com.devpath.api.builder.service;

import com.devpath.api.builder.dto.MyRoadmapResponse;
import com.devpath.api.builder.dto.MyRoadmapSaveRequest;
import com.devpath.api.builder.dto.MyRoadmapSummary;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.builder.entity.BuilderModule;
import com.devpath.domain.builder.entity.MyRoadmap;
import com.devpath.domain.builder.entity.MyRoadmapModule;
import com.devpath.domain.builder.repository.BuilderModuleRepository;
import com.devpath.domain.builder.repository.MyRoadmapRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MyRoadmapService {

  private final MyRoadmapRepository myRoadmapRepository;
  private final BuilderModuleRepository builderModuleRepository;
  private final UserRepository userRepository;

  @Transactional
  public MyRoadmapResponse save(Long userId, MyRoadmapSaveRequest request) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

    // 요청된 모든 builderModuleId를 한 번에 조회
    List<Long> moduleIds = request.getModules().stream()
        .map(MyRoadmapSaveRequest.ModuleItem::getBuilderModuleId)
        .toList();

    Map<Long, BuilderModule> moduleMap = builderModuleRepository.findAllById(moduleIds)
        .stream()
        .collect(Collectors.toMap(BuilderModule::getId, m -> m));

    // 요청에 없는 moduleId 검증
    for (Long id : moduleIds) {
      if (!moduleMap.containsKey(id)) {
        throw new CustomException(ErrorCode.BUILDER_MODULE_NOT_FOUND);
      }
    }

    MyRoadmap myRoadmap = MyRoadmap.builder()
        .user(user)
        .title(request.getTitle())
        .build();

    // 요청 순서 보장 — moduleMap에서 꺼내 MyRoadmapModule 생성
    request.getModules().forEach(item -> {
      MyRoadmapModule module = MyRoadmapModule.builder()
          .myRoadmap(myRoadmap)
          .builderModule(moduleMap.get(item.getBuilderModuleId()))
          .sortOrder(item.getSortOrder())
          .branchGroup(item.getBranchGroup())
          .build();
      myRoadmap.addModule(module);
    });

    myRoadmapRepository.save(myRoadmap);
    return MyRoadmapResponse.from(myRoadmap);
  }

  @Transactional(readOnly = true)
  public List<MyRoadmapSummary> findAll(Long userId) {
    return myRoadmapRepository.findSummariesByUserId(userId);
  }

  @Transactional(readOnly = true)
  public MyRoadmapResponse findById(Long userId, Long myRoadmapId) {
    MyRoadmap myRoadmap = myRoadmapRepository.findByIdWithModules(myRoadmapId, userId)
        .orElseThrow(() -> new CustomException(ErrorCode.MY_ROADMAP_NOT_FOUND));
    return MyRoadmapResponse.from(myRoadmap);
  }

  @Transactional
  public void delete(Long userId, Long myRoadmapId) {
    MyRoadmap myRoadmap = myRoadmapRepository.findByIdWithModules(myRoadmapId, userId)
        .orElseThrow(() -> new CustomException(ErrorCode.MY_ROADMAP_NOT_FOUND));
    myRoadmapRepository.delete(myRoadmap);
  }
}