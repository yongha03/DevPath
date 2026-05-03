package com.devpath.domain.application.repository;

import com.devpath.domain.application.entity.LoungeApplication;
import com.devpath.domain.application.entity.LoungeApplicationType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoungeApplicationRepository extends JpaRepository<LoungeApplication, Long> {

  // 같은 대상에게 같은 타입의 신청서/제안서를 중복 생성하지 못하게 막는다.
  boolean existsByTypeAndTargetIdAndSender_IdAndReceiver_IdAndIsDeletedFalse(
      LoungeApplicationType type, Long targetId, Long senderId, Long receiverId);

  // 보낸 신청 목록 조회에서 sender, receiver 정보를 함께 로딩한다.
  @EntityGraph(attributePaths = {"sender", "receiver"})
  List<LoungeApplication> findAllBySender_IdAndIsDeletedFalseOrderByCreatedAtDesc(Long senderId);

  // 받은 요청 목록 조회에서 sender, receiver 정보를 함께 로딩한다.
  @EntityGraph(attributePaths = {"sender", "receiver"})
  List<LoungeApplication> findAllByReceiver_IdAndIsDeletedFalseOrderByCreatedAtDesc(
      Long receiverId);

  // 단건 조회와 상태 조회에서 Soft Delete 된 데이터는 제외한다.
  @EntityGraph(attributePaths = {"sender", "receiver"})
  Optional<LoungeApplication> findByIdAndIsDeletedFalse(Long id);
}
