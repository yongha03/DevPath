package com.devpath.api.instructor.controller;

import com.devpath.api.instructor.dto.marketing.ConversionResponse;
import com.devpath.api.instructor.dto.marketing.CouponCreateRequest;
import com.devpath.api.instructor.dto.marketing.CouponListResponse;
import com.devpath.api.instructor.dto.marketing.CouponResponse;
import com.devpath.api.instructor.dto.marketing.PromotionCreateRequest;
import com.devpath.api.instructor.dto.marketing.PromotionListResponse;
import com.devpath.api.instructor.dto.marketing.PromotionStatusUpdateRequest;
import com.devpath.api.instructor.service.InstructorMarketingService;
import com.devpath.common.response.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Instructor - Marketing", description = "Instructor marketing API")
@RestController
@RequestMapping("/api/instructor/marketing")
@RequiredArgsConstructor
public class InstructorMarketingController {

    private final InstructorMarketingService instructorMarketingService;

    @Operation(summary = "Create coupon")
    @PostMapping("/coupons")
    public ApiResponse<CouponResponse> createCoupon(
            @RequestBody @Valid CouponCreateRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Coupon created.", instructorMarketingService.createCoupon(userId, request));
    }

    @Operation(summary = "List coupons")
    @GetMapping("/coupons")
    public ApiResponse<List<CouponListResponse>> getCoupons(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Coupons loaded.", instructorMarketingService.getCoupons(userId));
    }

    @Operation(summary = "Create promotion")
    @PostMapping("/promotions")
    public ApiResponse<Void> createPromotion(
            @RequestBody @Valid PromotionCreateRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorMarketingService.createPromotion(userId, request);
        return ApiResponse.success("Promotion created.", null);
    }

    @Operation(summary = "List promotions")
    @GetMapping("/promotions")
    public ApiResponse<List<PromotionListResponse>> getPromotions(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Promotions loaded.", instructorMarketingService.getPromotions(userId));
    }

    @Operation(summary = "Update promotion status")
    @PatchMapping("/courses/{courseId}/promotion-status")
    public ApiResponse<Void> updatePromotionStatus(
            @PathVariable Long courseId,
            @RequestBody @Valid PromotionStatusUpdateRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        instructorMarketingService.updatePromotionStatus(courseId, userId, request);
        return ApiResponse.success("Promotion status updated.", null);
    }

    @Operation(summary = "Get conversion stats")
    @GetMapping("/conversions")
    public ApiResponse<ConversionResponse> getConversions(
            @Parameter(hidden = true) @AuthenticationPrincipal Long userId
    ) {
        return ApiResponse.success("Conversion stats loaded.", instructorMarketingService.getConversions(userId));
    }
}
