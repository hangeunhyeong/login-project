package tave.login.config;

import lombok.AllArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tave.login.domain.jwt.repository.RefreshRepository;

import java.time.LocalDateTime;
// 사용자가 브라우저를 일주일 동안 켜두고 로그아웃을 하지 않는 경우 -> 스케줄링 필요
@AllArgsConstructor
@Component
public class ScheduleConfig {
    private final RefreshRepository refreshRepository;
    // Refresh 토큰 저장소 8일 지난 토큰 삭제(새벽 3시 실행)
    @Scheduled(cron = "0 0 3 * * *")    // 초 분 시 일 월 요일
    @Transactional
    public void refreshEntityTtlSchedule() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(8);
        refreshRepository.deleteByCreatedDateBefore(cutoff);
    }

}
