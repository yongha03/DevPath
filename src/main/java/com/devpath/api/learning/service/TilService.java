package com.devpath.api.learning.service;

import com.devpath.api.learning.dto.TilPublishRequest;
import com.devpath.api.learning.dto.TilPublishResponse;
import com.devpath.api.learning.dto.TilRequest;
import com.devpath.api.learning.dto.TilResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.course.entity.Lesson;
import com.devpath.domain.course.repository.LessonRepository;
import com.devpath.domain.learning.entity.TilDraft;
import com.devpath.domain.learning.entity.TimestampNote;
import com.devpath.domain.learning.repository.TilDraftRepository;
import com.devpath.domain.learning.repository.TimestampNoteRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TilService {

    private final TilDraftRepository tilDraftRepository;
    private final TimestampNoteRepository timestampNoteRepository;
    private final LessonRepository lessonRepository;
    private final UserRepository userRepository;

    // TIL 초안 저장
    @Transactional
    public TilResponse createTil(Long userId, TilRequest.Create request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        Lesson lesson = null;
        if (request.getLessonId() != null) {
            lesson = lessonRepository.findById(request.getLessonId())
                    .orElseThrow(() -> new CustomException(ErrorCode.LESSON_NOT_FOUND));
        }

        TilDraft til = TilDraft.builder()
                .user(user)
                .lesson(lesson)
                .title(request.getTitle())
                .content(request.getContent())
                .build();

        return TilResponse.from(tilDraftRepository.save(til));
    }

    // TIL 단건 조회
    @Transactional(readOnly = true)
    public TilResponse getTil(Long userId, Long tilId) {
        TilDraft til = tilDraftRepository.findByIdAndUserIdAndIsDeletedFalse(tilId, userId)
                .orElseThrow(() -> new CustomException(ErrorCode.TIL_NOT_FOUND));

        return TilResponse.from(til);
    }

    // TIL 목록 조회
    @Transactional(readOnly = true)
    public List<TilResponse> getTilList(Long userId) {
        return tilDraftRepository.findByUserIdAndIsDeletedFalseOrderByCreatedAtDesc(userId)
                .stream()
                .map(TilResponse::from)
                .collect(Collectors.toList());
    }

    // TIL 수정
    @Transactional
    public TilResponse updateTil(Long userId, Long tilId, TilRequest.Update request) {
        TilDraft til = tilDraftRepository.findByIdAndUserIdAndIsDeletedFalse(tilId, userId)
                .orElseThrow(() -> new CustomException(ErrorCode.TIL_NOT_FOUND));

        til.updateContent(request.getTitle(), request.getContent());
        return TilResponse.from(til);
    }

    // 노트 목록 -> TIL 초안 자동 변환
    // 타임스탬프 순으로 정렬 후 노트 내용을 마크다운으로 이어 붙여 TIL 본문을 생성한다.
    @Transactional
    public TilResponse convertFromNotes(Long userId, TilRequest.ConvertFromNotes request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        Lesson lesson = null;
        if (request.getLessonId() != null) {
            lesson = lessonRepository.findById(request.getLessonId())
                    .orElseThrow(() -> new CustomException(ErrorCode.LESSON_NOT_FOUND));
        }

        List<TimestampNote> notes = request.getNoteIds().stream()
                .map(noteId -> timestampNoteRepository.findByIdAndUserIdAndIsDeletedFalse(noteId, userId)
                        .orElseThrow(() -> new CustomException(ErrorCode.TIMESTAMP_NOTE_NOT_FOUND)))
                .sorted(Comparator.comparingInt(TimestampNote::getTimestampSecond))
                .collect(Collectors.toList());

        // 타임스탬프를 mm:ss 형식으로 변환하여 마크다운 본문 구성
        String content = notes.stream()
                .map(note -> {
                    int sec = note.getTimestampSecond();
                    String timestamp = String.format("%02d:%02d", sec / 60, sec % 60);
                    return "## [" + timestamp + "]\n" + note.getContent();
                })
                .collect(Collectors.joining("\n\n"));

        TilDraft til = TilDraft.builder()
                .user(user)
                .lesson(lesson)
                .title(request.getTitle())
                .content(content)
                .build();

        return TilResponse.from(tilDraftRepository.save(til));
    }

    // 기존 publish 메서드는 userId, tilId 만 받았지만
    // 이제 외부 블로그 발행 요청 body 를 함께 받아 계약을 맞춘다.
    @Transactional
    public TilPublishResponse publishToExternalBlog(Long userId, Long tilId, TilPublishRequest request) {
        TilDraft til = tilDraftRepository.findByIdAndUserIdAndIsDeletedFalse(tilId, userId)
                .orElseThrow(() -> new CustomException(ErrorCode.TIL_NOT_FOUND));

        // 외부 발행 요청값을 기준으로 제목/본문을 최신화한다.
        // 실제 외부 플랫폼 연동 전까지는 내부 TIL 데이터와 외부 발행 payload 를 동일하게 맞춘다.
        til.updateContent(request.getTitle(), request.getContent());

        // platform 문자열을 정규화한다.
        String normalizedPlatform = normalizePlatform(request.getPlatform());

        // 현재는 stub 구현이므로 mock external post id 를 생성한다.
        String externalPostId = buildMockExternalPostId(tilId);

        // 테스트 기대치에 맞춰 mock.blog.devpath 형식의 URL을 생성한다.
        String publishedUrl = buildPublishedUrl(normalizedPlatform, externalPostId);

        // 엔티티에는 publishedUrl 과 status 만 저장한다.
        til.publish(publishedUrl);

        return TilPublishResponse.builder()
                .tilId(til.getId())
                .published(true)
                .platform(normalizedPlatform)
                .externalPostId(externalPostId)
                .publishedUrl(publishedUrl)
                .draft(Boolean.TRUE.equals(request.getDraft()))
                .publishedAt(LocalDateTime.now())
                .build();
    }

    // TIL 본문의 마크다운 헤더(#, ##, ###)를 파싱하여 목차 JSON 문자열을 생성하고 저장한다.
    // 목차 형식: [{"level":1,"title":"제목","anchor":"제목"},...]
    @Transactional
    public TilResponse generateTableOfContents(Long userId, Long tilId) {
        TilDraft til = tilDraftRepository.findByIdAndUserIdAndIsDeletedFalse(tilId, userId)
                .orElseThrow(() -> new CustomException(ErrorCode.TIL_NOT_FOUND));

        String toc = buildTableOfContents(til.getContent());
        til.updateTableOfContents(toc);

        return TilResponse.from(til);
    }

    // 마크다운 헤더 파싱 후 JSON 배열 문자열로 반환하는 내부 유틸 메서드
    private String buildTableOfContents(String content) {
        Pattern pattern = Pattern.compile("^(#{1,3})\\s+(.+)$", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(content);
        List<String> entries = new ArrayList<>();

        while (matcher.find()) {
            int level = matcher.group(1).length();
            String title = matcher.group(2).trim();
            String anchor = title.toLowerCase()
                    .replaceAll("[^a-z0-9가-힣\\s]", "")
                    .trim()
                    .replaceAll("\\s+", "-");

            entries.add(String.format(
                    "{\"level\":%d,\"title\":\"%s\",\"anchor\":\"%s\"}",
                    level,
                    title,
                    anchor
            ));
        }

        return "[" + String.join(",", entries) + "]";
    }

    // 외부 발행 플랫폼 문자열을 대문자로 정규화한다.
    private String normalizePlatform(String platform) {
        return platform.trim().toUpperCase(Locale.ROOT);
    }

    // mock/stub 외부 게시글 ID 를 생성한다.
    private String buildMockExternalPostId(Long tilId) {
        return "mock-post-" + tilId + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    // 현재는 플랫폼별 실제 Provider 연동 대신 공통 mock URL 을 사용한다.
    private String buildPublishedUrl(String platform, String externalPostId) {
        return "https://mock.blog.devpath/posts/" + externalPostId;
    }
}
