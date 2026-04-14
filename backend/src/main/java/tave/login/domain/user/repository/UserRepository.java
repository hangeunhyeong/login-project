package tave.login.domain.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tave.login.domain.user.entity.UserEntity;

import java.util.Optional;

public interface UserRepository  extends JpaRepository<UserEntity, Long> {
    Boolean existsByUsername(String username);
    Optional<UserEntity> findByUsernameAndIsLockAndIsSocial(String username, Boolean isLock, Boolean isSocial);
    Optional<UserEntity> findByUsernameAndIsSocial(String username, boolean b);
    void deleteByUsername(String username);
    Optional<UserEntity> findByUsernameAndIsLock(String username, boolean isLock);
}
