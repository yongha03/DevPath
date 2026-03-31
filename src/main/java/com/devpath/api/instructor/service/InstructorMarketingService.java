package com.devpath.api.instructor.service;

import com.devpath.api.instructor.dto.marketing.ConversionResponse;
import com.devpath.api.instructor.dto.marketing.CouponCreateRequest;
import com.devpath.api.instructor.dto.marketing.CouponResponse;
import com.devpath.api.instructor.dto.marketing.PromotionCreateRequest;
import com.devpath.api.instructor.dto.marketing.PromotionStatusUpdateRequest;
import com.devpath.api.instructor.entity.ConversionStat;
import com.devpath.api.instructor.entity.Coupon;
import com.devpath.api.instructor.entity.Promotion;
import com.devpath.api.instructor.repository.ConversionStatRepository;
import com.devpath.api.instructor.repository.CouponRepository;
import com.devpath.api.instructor.repository.PromotionRepository;
import com.devpath.common.exception.CustomException;
import com.devpath.common.exception.ErrorCode;
import com.devpath.domain.course.repository.CourseRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class InstructorMarketingService {

    private final CouponRepository couponRepository;
    private final PromotionRepository promotionRepository;
    private final ConversionStatRepository conversionStatRepository;
    private final CourseRepository courseRepository;

    public CouponResponse createCoupon(Long instructorId, CouponCreateRequest request) {
        validateTargetCourse(instructorId, request.getTargetCourseId());
        validateDiscount(request.getDiscountType(), request.getDiscountValue());

        if (request.getMaxUsageCount() != null && request.getMaxUsageCount() <= 0) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        if (request.getExpiresAt() != null && !request.getExpiresAt().isAfter(LocalDateTime.now())) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        Coupon coupon = Coupon.builder()
                .instructorId(instructorId)
                .couponCode(generateCouponCode())
                .discountType(normalizeDiscountType(request.getDiscountType()))
                .discountValue(request.getDiscountValue())
                .targetCourseId(request.getTargetCourseId())
                .maxUsageCount(request.getMaxUsageCount())
                .expiresAt(request.getExpiresAt())
                .build();

        return CouponResponse.from(couponRepository.save(coupon));
    }

    public void createPromotion(Long instructorId, PromotionCreateRequest request) {
        validateTargetCourse(instructorId, request.getCourseId());

        if (!request.getEndAt().isAfter(request.getStartAt())) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        if (request.getDiscountRate() <= 0 || request.getDiscountRate() > 100) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        Promotion promotion = Promotion.builder()
                .instructorId(instructorId)
                .courseId(request.getCourseId())
                .promotionType(request.getPromotionType())
                .discountRate(request.getDiscountRate())
                .startAt(request.getStartAt())
                .endAt(request.getEndAt())
                .build();

        promotionRepository.save(promotion);
    }

    public void updatePromotionStatus(Long courseId, Long instructorId, PromotionStatusUpdateRequest request) {
        Promotion promotion = promotionRepository
                .findTopByCourseIdAndInstructorIdAndIsDeletedFalseOrderByCreatedAtDesc(courseId, instructorId)
                .orElseThrow(() -> new CustomException(ErrorCode.PROMOTION_NOT_FOUND));

        promotion.updateStatus(request.getStatus());
    }

    @Transactional(readOnly = true)
    public ConversionResponse getConversions(Long instructorId) {
        ConversionStat overall = conversionStatRepository
                .findTopByInstructorIdAndCourseIdIsNullOrderByCalculatedAtDesc(instructorId)
                .orElse(null);

        long totalVisitors = overall == null ? 0L : overall.getTotalVisitors();
        long totalSignups = overall == null ? 0L : overall.getTotalSignups();
        long totalPurchases = overall == null ? 0L : overall.getTotalPurchases();

        double signupRate = calculateRate(totalVisitors, totalSignups);
        double purchaseRate = calculateRate(totalVisitors, totalPurchases);

        long dailySnapshotCount = conversionStatRepository.countByInstructorIdAndCourseIdIsNullAndCalculatedAtAfter(
                instructorId,
                LocalDateTime.now().minusDays(1)
        );

        long weeklySnapshotCount = conversionStatRepository.countByInstructorIdAndCourseIdIsNullAndCalculatedAtAfter(
                instructorId,
                LocalDateTime.now().minusDays(7)
        );

        List<ConversionStat> courseStats =
                conversionStatRepository.findByInstructorIdAndCourseIdIsNotNullOrderByCalculatedAtDesc(instructorId);
        Map<Long, ConversionStat> latestByCourse = new LinkedHashMap<>();

        for (ConversionStat stat : courseStats) {
            if (stat.getCourseId() != null && !latestByCourse.containsKey(stat.getCourseId())) {
                latestByCourse.put(stat.getCourseId(), stat);
            }
        }

        List<ConversionResponse.CourseConversionItem> courseConversions = new ArrayList<>();
        for (ConversionStat stat : latestByCourse.values()) {
            courseConversions.add(
                    ConversionResponse.CourseConversionItem.builder()
                            .courseId(stat.getCourseId())
                            .totalVisitors(stat.getTotalVisitors())
                            .totalSignups(stat.getTotalSignups())
                            .totalPurchases(stat.getTotalPurchases())
                            .signupRate(calculateRate(stat.getTotalVisitors(), stat.getTotalSignups()))
                            .purchaseRate(calculateRate(stat.getTotalVisitors(), stat.getTotalPurchases()))
                            .calculatedAt(stat.getCalculatedAt())
                            .build()
            );
        }

        return ConversionResponse.builder()
                .totalVisitors(totalVisitors)
                .totalSignups(totalSignups)
                .totalPurchases(totalPurchases)
                .signupRate(signupRate)
                .purchaseRate(purchaseRate)
                .dailySnapshotCount(dailySnapshotCount)
                .weeklySnapshotCount(weeklySnapshotCount)
                .courseConversions(courseConversions)
                .build();
    }

    // 쿠폰 코드는 충돌이 날 때까지 재생성한다.
    private String generateCouponCode() {
        String code;
        do {
            code = UUID.randomUUID().toString().replace("-", "").substring(0, 8).toUpperCase(Locale.ROOT);
        } while (couponRepository.existsByCouponCode(code));

        return code;
    }

    // 타겟 강의가 있으면 반드시 본인 강의여야 한다.
    private void validateTargetCourse(Long instructorId, Long courseId) {
        if (courseId == null) {
            return;
        }

        if (!courseRepository.existsByCourseIdAndInstructorId(courseId, instructorId)) {
            throw new CustomException(ErrorCode.COURSE_NOT_FOUND);
        }
    }

    // 할인 타입과 값은 운영에서 RATE/AMOUNT 두 가지만 허용한다.
    private void validateDiscount(String discountType, Long discountValue) {
        String normalizedType = normalizeDiscountType(discountType);

        if (discountValue == null || discountValue <= 0) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        if ("RATE".equals(normalizedType) && discountValue > 100) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }
    }

    private String normalizeDiscountType(String discountType) {
        if (discountType == null || discountType.isBlank()) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        String normalized = discountType.trim().toUpperCase(Locale.ROOT);
        if (!normalized.equals("RATE") && !normalized.equals("AMOUNT")) {
            throw new CustomException(ErrorCode.INVALID_INPUT);
        }

        return normalized;
    }

    private double calculateRate(long denominator, long numerator) {
        if (denominator == 0) {
            return 0.0;
        }
        return Math.round((numerator * 10000.0 / denominator)) / 100.0;
    }
}
