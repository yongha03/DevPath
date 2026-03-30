package com.devpath.api.admin.service;

import com.devpath.api.admin.dto.settlement.SettlementEligibilityResponse;
import com.devpath.api.admin.dto.settlement.SettlementHoldRequest;
import com.devpath.api.refund.entity.RefundRequest;
import com.devpath.api.refund.repository.RefundRepository;
import com.devpath.api.settlement.entity.Settlement;
import com.devpath.api.settlement.entity.SettlementHold;
import com.devpath.api.settlement.repository.SettlementHoldRepository;
import com.devpath.api.settlement.repository.SettlementRepository;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminSettlementService {

    private final SettlementRepository settlementRepository;
    private final SettlementHoldRepository settlementHoldRepository;
    private final RefundRepository refundRepository;

    public void holdSettlement(Long settlementId, Long adminId, SettlementHoldRequest request) {
        Settlement settlement = settlementRepository.findByIdAndIsDeletedFalse(settlementId)
                .orElseThrow(() -> new CustomException(ErrorCode.SETTLEMENT_NOT_FOUND));

        settlement.hold();

        settlementHoldRepository.save(
                SettlementHold.builder()
                        .settlementId(settlement.getId())
                        .adminId(adminId)
                        .reason(request.getReason())
                        .build()
        );
    }

    @Transactional(readOnly = true)
    public SettlementEligibilityResponse checkEligibility(Long refundRequestId) {
        RefundRequest refundRequest = refundRepository.findByIdAndIsDeletedFalse(refundRequestId)
                .orElseThrow(() -> new CustomException(ErrorCode.REFUND_NOT_FOUND));

        LocalDateTime purchasedAt = refundRequest.getRequestedAt();
        LocalDateTime refundDeadline = purchasedAt.plusDays(7);
        LocalDateTime now = LocalDateTime.now();

        boolean isEligible = now.isBefore(refundDeadline);
        long remainingDays = Math.max(0, ChronoUnit.DAYS.between(now, refundDeadline));

        return SettlementEligibilityResponse.builder()
                .refundRequestId(refundRequestId)
                .courseId(refundRequest.getCourseId())
                .learnerId(refundRequest.getLearnerId())
                .purchasedAt(purchasedAt)
                .refundDeadline(refundDeadline)
                .isEligible(isEligible)
                .remainingDays(remainingDays)
                .build();
    }
}
