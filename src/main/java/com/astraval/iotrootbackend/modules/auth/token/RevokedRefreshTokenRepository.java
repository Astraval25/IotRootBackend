package com.astraval.iotrootbackend.modules.auth.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RevokedRefreshTokenRepository extends JpaRepository<RevokedRefreshToken, Long> {

    boolean existsByTokenId(String tokenId);
}
