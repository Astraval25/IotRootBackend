package com.astraval.iotrootbackend.modules.user;

import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

  private final UserRepository userRepository;

  public UserService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Transactional(readOnly = true)
  public Optional<User> findUserById(Long userId) {
    return userRepository.findByUserIdAndIsActiveTrue(userId);
  }

  @Transactional(readOnly = true)
  public Optional<User> findUserByEmail(String email) {
    return userRepository.findByEmailIgnoreCaseAndIsActiveTrue(email);
  }

  @Transactional
  public User saveUser(User user) {
    return userRepository.save(user);
  }

}
