package com.hawk.spring_secuirity.token;

import com.hawk.spring_secuirity.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {
    @Id
    @GeneratedValue
    private Integer Id;
    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType type;
    private boolean expired;
    private boolean revoked;
    @SuppressWarnings("JpaDataSourceORMInspection")
    @ManyToOne
    @JoinColumn(name="user_id")
    private User user;
}
