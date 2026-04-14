package tave.login.domain.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;
import tave.login.domain.jwt.entity.RefreshEntity;

import java.time.LocalDateTime;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long>{
    Boolean existsByRefresh(String refresh);
    void deleteByRefresh(String refresh);
    void deleteByUsername(String username);
    void deleteByCreatedDateBefore(LocalDateTime cutoff);
}
