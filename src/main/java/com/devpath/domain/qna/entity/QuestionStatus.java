package com.devpath.domain.qna.entity;

public enum QuestionStatus {

  // 아직 답변이 등록되지 않은 질문 상태
  WAITING,

  // 답변이 1개 이상 등록된 질문 상태
  ANSWERED,

  // 작성자 또는 운영자가 더 이상 답변을 받지 않도록 닫은 상태
  CLOSED
}
