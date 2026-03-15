package com.devpath.api.admin.service;

import com.devpath.api.admin.dto.TagGovernanceRequests.*;
import com.devpath.api.admin.dto.TagResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.user.entity.Tag;
import com.devpath.domain.user.repository.TagRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminTagGovernanceService {

    private final TagRepository tagRepository;

    // 1. 표준 태그 등록
    public void createTag(CreateTag request) {
        // 실제 스키마에 맞게 객체 생성
        Tag newTag = Tag.builder()
                .name(request.getName())
                .category(request.getCategory())
                .build();

        tagRepository.save(newTag);
    }

    // 2. 표준 태그 수정
    public void updateTag(Long tagId, UpdateTag request) {
        Tag tag = tagRepository.findById(tagId)
                .orElseThrow(() -> new CustomException(ErrorCode.TAG_NOT_FOUND));

        // 엔티티에 만들어둔 비즈니스 메서드 사용 (기존에 정의된 메서드 활용)
        tag.updateTagInfo(request.getName(), request.getCategory());
    }

    // 3. 전체 태그 조회
    @Transactional(readOnly = true)
    public List<TagResponse> getAllTags() {
        return tagRepository.findAll().stream()
                .map(TagResponse::from)
                .collect(Collectors.toList());
    }

    // 4. 태그 병합 (중복 제거)
    public void mergeTags(MergeTags request) {
        Tag sourceTag = tagRepository.findById(request.getSourceTagId())
                .orElseThrow(() -> new CustomException(ErrorCode.TAG_NOT_FOUND));
        Tag targetTag = tagRepository.findById(request.getTargetTagId())
                .orElseThrow(() -> new CustomException(ErrorCode.TAG_NOT_FOUND));

        // TODO: 향후 CourseTagMap 등 연관 데이터 치환 로직 구현
        tagRepository.delete(sourceTag);
    }

    // 5. 표준 용어 가이드 조회
    @Transactional(readOnly = true)
    public String getTagGuide() {
        return "1. 모든 태그는 소문자로 작성합니다.\n" +
                "2. 띄어쓰기는 하이픈(-)으로 대체합니다. (예: Spring Boot -> spring-boot)\n" +
                "3. 약어보다는 풀네임 사용을 권장합니다.";
    }
}