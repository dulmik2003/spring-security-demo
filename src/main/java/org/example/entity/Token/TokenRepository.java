package org.example.entity.Token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {
    @Query("""
                select t from Token t inner join User u on t.user.id = u.id
                where u.id = :userId and t.isRevoked = false
            """)
    List<Token> findAllValidTokensByUser(Integer userId);

    //todo
    // get a 'token object' by it's JWT(Jason Web Token)
    Optional<Token> findByToken(String token);
}
