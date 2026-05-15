package com.devpath.api.job.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

public class JobkoreaJobRequest {

  private JobkoreaJobRequest() {}

  @Schema(name = "JobkoreaJobSearchRequest", description = "잡코리아 채용공고 XML 조회 조건")
  public record Search(
      @Schema(description = "조회 건수. 잡코리아 최대값은 100입니다.", example = "20")
          @Min(value = 1, message = "조회 건수는 1 이상이어야 합니다.")
          @Max(value = 100, message = "잡코리아 조회 건수는 100 이하여야 합니다.")
          Integer size,
      @Schema(description = "페이지 번호", example = "1")
          @Min(value = 1, message = "페이지 번호는 1 이상이어야 합니다.")
          Integer page,
      @Schema(description = "정렬 순서. 1 등록일순, 2 수정일순, 3 마감일순", example = "1")
          @Min(value = 1, message = "정렬 순서는 1 이상이어야 합니다.")
          @Max(value = 3, message = "정렬 순서는 3 이하여야 합니다.")
          Integer order,
      @Schema(description = "검색어. 잡코리아 API에는 EUC-KR로 인코딩되어 전달됩니다.", example = "Spring Boot")
          @Size(max = 100, message = "검색어는 100자 이하여야 합니다.")
          String keyword,
      @Schema(description = "업·직종 대분류 코드", example = "10031")
          @Size(max = 30, message = "업·직종 대분류 코드는 30자 이하여야 합니다.")
          String industryCode,
      @Schema(description = "업·직종 소분류 코드", example = "1000229")
          @Size(max = 30, message = "업·직종 소분류 코드는 30자 이하여야 합니다.")
          String jobCode,
      @Schema(description = "근무지역 코드. 복수 값은 콤마로 전달합니다.", example = "I000")
          @Size(max = 100, message = "근무지역 코드는 100자 이하여야 합니다.")
          String areaCode,
      @Schema(description = "신입공채 XML 사용 여부", example = "false") Boolean starter) {}
}
