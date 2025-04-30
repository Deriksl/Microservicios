package com.imt.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    @Modifying
    @Transactional
    @Query(value = """
        INSERT INTO login_attempts 
        (user_id, ip_address, user_agent, success, attempted_at) 
        VALUES (:userId, :ipAddress, :userAgent, true, NOW())
        """, nativeQuery = true)
    void registerSuccessfulLogin(Long userId, String ipAddress, String userAgent);
}