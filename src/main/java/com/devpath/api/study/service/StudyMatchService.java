package com.devpath.api.study.service;

import com.devpath.api.study.dto.StudyMatchRecommendationResponse;
import com.devpath.api.study.dto.StudyMatchResponse;
import com.devpath.domain.study.repository.StudyMatchRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StudyMatchService {

    private final StudyMatchRepository studyMatchRepository;

    // 1. 내 매칭 내역 조회
    public List<StudyMatchResponse> getMyMatches(Long learnerId) {
        return studyMatchRepository.findMyMatches(learnerId).stream()
                .map(StudyMatchResponse::from)
                .collect(Collectors.toList());
    }

    // 2. 같은 노드를 듣는 학습자 자동 추천 (Mock 데이터 반환)
    // 실제 운영에서는 A 파트의 NodeProgress 데이터를 조인하여 복잡한 추천 쿼리를 실행합니다.
    public List<StudyMatchRecommendationResponse> getRecommendations(Long learnerId) {
        // C 파트 독립 테스트를 위해 더미 추천 데이터 2건 반환
        return List.of(
                StudyMatchRecommendationResponse.builder()
                        .recommendedLearnerId(2L)
                        .maskedName("이*엔")
                        .sharedNodeId(15L)
                        .matchScore(98)
                        .build(),
                StudyMatchRecommendationResponse.builder()
                        .recommendedLearnerId(3L)
                        .maskedName("박*트")
                        .sharedNodeId(15L)
                        .matchScore(85)
                        .build()
        );
    }
}