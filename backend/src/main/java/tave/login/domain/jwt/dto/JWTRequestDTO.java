package tave.login.domain.jwt.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JWTRequestDTO {
    @NotBlank
    private String refreshToken;
}
