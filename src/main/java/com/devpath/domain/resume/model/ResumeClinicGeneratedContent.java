package com.devpath.domain.resume.model;

import java.util.List;

public record ResumeClinicGeneratedContent(
    ResumeClinicSourceType sourceType, String title, String content, List<String> keywords) {}
