package tave.login.domain.user.entity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import tave.login.domain.user.dto.UserRequestDTO;

import java.time.LocalDateTime;

@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "user_user_entity")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", unique = true, nullable = false, updatable = false)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    // 계정이 잠겼는지 확인
    @Column(name = "is_lock", nullable = false)
    private Boolean isLock;

    // 소셜로그인 계정인지
    @Column(name = "is_social", nullable = false)
    private Boolean isSocial;

    // 소셜로그인이 아닌 경우 null
    @Enumerated(EnumType.STRING)
    @Column(name = "social_provider_type")
    private SocialProviderType socialProviderType;

    // admin인지 일반유저인지
    @Enumerated(EnumType.STRING)
    @Column(name = "role_type", nullable = false)
    private UserRoleType roleType;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "email")
    private String email;

    @CreatedDate
    @Column(name = "created_date", updatable = false)
    private LocalDateTime createdDate;

    @LastModifiedDate
    @Column(name = "updated_date")
    private LocalDateTime updatedDate;

    public void updateUser(UserRequestDTO dto) {
        this.email = dto.getEmail();
        this.nickname = dto.getNickname();
    }
}
