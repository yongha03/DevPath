package com.devpath.api.learning.service;

import com.devpath.api.learning.dto.TimestampNoteRequest;
import com.devpath.api.learning.dto.TimestampNoteResponse;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.course.entity.Lesson;
import com.devpath.domain.course.repository.LessonRepository;
import com.devpath.domain.learning.entity.TimestampNote;
import com.devpath.domain.learning.repository.TimestampNoteRepository;
import com.devpath.domain.user.entity.User;
import com.devpath.domain.user.repository.UserRepository;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TimestampNoteService {

    private final TimestampNoteRepository timestampNoteRepository;
    private final LessonRepository lessonRepository;
    private final UserRepository userRepository;

    @Transactional
    public TimestampNoteResponse createNote(Long userId, Long lessonId, TimestampNoteRequest.Create request) {
        Lesson lesson = lessonRepository.findById(lessonId)
                .orElseThrow(() -> new CustomException(ErrorCode.LESSON_NOT_FOUND));
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        TimestampNote note = TimestampNote.builder()
                .user(user)
                .lesson(lesson)
                .timestampSecond(normalizeTimestampSecond(request.getTimestampSecond()))
                .content(request.getContent())
                .build();

        return TimestampNoteResponse.from(timestampNoteRepository.save(note));
    }

    @Transactional(readOnly = true)
    public List<TimestampNoteResponse> getNotes(Long userId, Long lessonId) {
        return timestampNoteRepository
                .findByUserIdAndLessonLessonIdAndIsDeletedFalseOrderByTimestampSecondAsc(userId, lessonId)
                .stream()
                .map(TimestampNoteResponse::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public TimestampNoteResponse updateNote(Long userId, Long lessonId, Long noteId, TimestampNoteRequest.Update request) {
        TimestampNote note = timestampNoteRepository
                .findByIdAndUserIdAndIsDeletedFalse(noteId, userId)
                .orElseThrow(() -> new CustomException(ErrorCode.TIMESTAMP_NOTE_NOT_FOUND));

        if (!note.getLesson().getLessonId().equals(lessonId)) {
            throw new CustomException(ErrorCode.TIMESTAMP_NOTE_NOT_FOUND);
        }

        note.updateContent(normalizeTimestampSecond(request.getTimestampSecond()), request.getContent());

        return TimestampNoteResponse.from(note);
    }

    @Transactional
    public void deleteNote(Long userId, Long noteId) {
        TimestampNote note = timestampNoteRepository
                .findByIdAndUserIdAndIsDeletedFalse(noteId, userId)
                .orElseThrow(() -> new CustomException(ErrorCode.TIMESTAMP_NOTE_NOT_FOUND));

        note.delete();
    }

    private Integer normalizeTimestampSecond(Integer timestampSecond) {
        if (timestampSecond == null || timestampSecond < 0) {
            return 0;
        }
        return timestampSecond;
    }
}
