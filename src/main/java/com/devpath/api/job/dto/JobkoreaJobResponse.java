package com.devpath.api.job.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.LocalDate;
import java.util.List;

public class JobkoreaJobResponse {

  private JobkoreaJobResponse() {}

  @Schema(name = "JobkoreaJobSearchResponse", description = "잡코리아 채용공고 XML 조회 결과")
  public record SearchResult(
      @Schema(description = "검색결과 총 건수. 잡코리아 응답의 TotalSumCnt입니다.", example = "500")
          Integer totalCount,
      @Schema(description = "현재 페이지 결과 건수. 잡코리아 응답의 TotalCnt입니다.", example = "20")
          Integer pageCount,
      @Schema(description = "요청 페이지 번호", example = "1") Integer page,
      @Schema(description = "요청 조회 건수", example = "20") Integer size,
      @Schema(description = "신입공채 XML 사용 여부", example = "false") Boolean starter,
      @Schema(description = "잡코리아 출처 표기 정보") Attribution attribution,
      @Schema(description = "채용공고 목록") List<Posting> items) {}

  @Schema(name = "JobkoreaAttribution", description = "잡코리아 출처 표기 정보")
  public record Attribution(
      @Schema(description = "출처 라벨", example = "잡코리아 채용정보 더보기") String label,
      @Schema(description = "출처 링크", example = "https://www.jobkorea.co.kr") String url,
      @Schema(description = "공고 하단 안내문구") String notice) {

    public static Attribution jobkorea() {
      return new Attribution(
          "잡코리아 채용정보 더보기",
          "https://www.jobkorea.co.kr",
          "자세한 채용정보는 반드시 상세정보를 통해 확인하시기 바랍니다. "
              + "본 정보는 채용기업과 잡코리아의 동의 없이 무단전재 또는 재배포, 재가공할 수 없습니다.");
    }
  }

  @Schema(name = "JobkoreaPosting", description = "잡코리아 채용공고")
  public record Posting(
      @Schema(description = "잡코리아 채용공고 고유번호", example = "23592012") String externalId,
      @Schema(description = "기업명", example = "잡코리아") String companyName,
      @Schema(description = "기업정보 URL") String companyUrl,
      @Schema(description = "채용공고 제목") String title,
      @Schema(description = "채용 관련 업·직종 코드") String jobCategoryCode,
      @Schema(description = "경력조건 코드") String careerCode,
      @Schema(description = "경력년수 코드") String careerYearCode,
      @Schema(description = "급여유형 코드") String payCode,
      @Schema(description = "급여수준") String payTerm,
      @Schema(description = "학력제한 코드") String educationCode,
      @Schema(description = "공고 주요 키워드") List<String> keywords,
      @Schema(description = "접수방법 코드") String passType,
      @Schema(description = "근무형태 코드") String jobType,
      @Schema(description = "모집인원") String staff,
      @Schema(description = "채용직급/직책 코드") String positionCode,
      @Schema(description = "근무지역 코드") String areaCode,
      @Schema(description = "마감일") LocalDate deadline,
      @Schema(description = "등록일") LocalDate postedDate,
      @Schema(description = "수정일") LocalDate updatedDate,
      @Schema(description = "잡코리아 상세 공고 URL") String jobkoreaUrl) {}
}
