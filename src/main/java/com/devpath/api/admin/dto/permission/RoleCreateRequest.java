package com.devpath.api.admin.dto.permission;

import jakarta.validation.constraints.NotBlank;
import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RoleCreateRequest {

    @NotBlank
    private String roleName;

    private String description;

    // 권한 코드는 ADMIN_NOTICE_WRITE 같은 고정 문자열을 받는다.
    private List<String> permissionCodes;
}
