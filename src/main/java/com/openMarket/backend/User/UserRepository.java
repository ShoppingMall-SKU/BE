package com.openMarket.backend.User;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.*;


@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByName(String name);
    Optional<User> findByEmail(String email);
    List<User> findByRole(User.role role);

    Optional<User> findByRefreshToken(String refreshToken);


}
