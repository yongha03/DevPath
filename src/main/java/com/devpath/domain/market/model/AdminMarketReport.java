package com.devpath.domain.market.model;

import java.time.LocalDateTime;
import java.util.List;

public record AdminMarketReport(
    Long totalPostingCount,
    Long openPostingCount,
    Long closedPostingCount,
    Long draftPostingCount,
    Long analyzedSkillTagCount,
    List<MarketSkillStackTrend> topSkills,
    List<MarketJobTrend> topJobRoles,
    List<MarketIndicator> indicators,
    LocalDateTime generatedAt) {}
