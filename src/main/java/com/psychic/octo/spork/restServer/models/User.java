package com.psychic.octo.spork.restServer.models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "email")
        })
public class User{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @NotBlank
    @Size(max = 20)
    @Column(name = "username")
    private String userName;

    @NotBlank
    @Size(max = 50)
    @Email
    @Column(name = "email")
    private String email;

    @Size(max = 120)
    @Column(name = "password")
    @JsonIgnore
    private String password;

    private boolean accountNonLocked = true;
    private boolean accountNonExpired = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    private LocalDate credentialsExpiryDate;
    private LocalDate accountExpiryDate;

    private String twoFactorSecret;
    private boolean isTwoFactorEnabled = false;
    private String signUpMethod;

    @ManyToOne(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE})
    @JoinColumn(name = "role_id", referencedColumnName = "role_id")
    @JsonBackReference
    @ToString.Exclude
    private Role role;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdDate;

    @UpdateTimestamp
    private LocalDateTime updatedDate;

    /*
    *
    *   ALL USERS WILL HAVE THEIR USERNAME AND EMAIL IN LOWERCASE
    *
    */

    private User(Builder builder) {
        this.userName =builder.userName.toLowerCase();
        this.email = builder.email.toLowerCase();
        this.password = builder.password;
        this.accountNonLocked = builder.isAccountNonLocked;
        this.accountNonExpired = builder.isAccountNonExpired;
        this.credentialsNonExpired = builder.isCredentialsNonExpired;
        this.enabled = builder.isEnabled;
        this.credentialsExpiryDate = builder.credentialsExpiryDate;
        this.accountExpiryDate = builder.accountExpiryDate;
        this.isTwoFactorEnabled = builder.is2faEnabled;
        this.twoFactorSecret = builder.twoFactorSecret;
        this.signUpMethod = builder.signUpMethod;
        this.role = builder.role;
    }

    public static class Builder {
        private String userName;
        private String email;
        private String password;
        private boolean isAccountNonLocked;
        private boolean isAccountNonExpired;
        private boolean isCredentialsNonExpired;
        private boolean isEnabled;
        private LocalDate credentialsExpiryDate;
        private LocalDate accountExpiryDate;
        private boolean is2faEnabled;
        private String twoFactorSecret;
        private String signUpMethod;
        private Role role;

        public Builder userName(final String userName){
            this.userName = userName;
            return this;
        }

        public Builder email(final String email){
            this.email = email;
            return this;
        }

        public Builder password(final String password){
            this.password = password;
            return this;
        }

        public Builder is2faEnabled(final boolean is2faEnabled){
            this.is2faEnabled = is2faEnabled;
            return this;
        }

        public Builder role(final Role role ) {
            this.role = role;
            return this;
        }

        public Builder isAccountNonExpired(final boolean isAccountNonExpired){
            this.isAccountNonExpired = isAccountNonExpired;
            return this;
        }

        public Builder isAccountNonLocked(final boolean isAccountNonLocked){
            this.isAccountNonLocked = isAccountNonLocked;
            return this;
        }

        public Builder isCredentialsNonExpired(final boolean isCredentialsNonExpired){
            this.isCredentialsNonExpired = isCredentialsNonExpired;
            return this;
        }

        public Builder isEnabled(final boolean isEnabled){
            this.isEnabled = isEnabled;
            return this;
        }

        public Builder credentialsExpiryDate(final LocalDate credentialsExpiryDate){
            this.credentialsExpiryDate = credentialsExpiryDate;
            return this;
        }

        public Builder accountExpiryDate(final LocalDate accountExpiryDate){
            this.accountExpiryDate = accountExpiryDate;
            return this;
        }

        public Builder twoFactorSecret(final String twoFactorSecret){
            this.twoFactorSecret = twoFactorSecret;
            return this;
        }

        public Builder signUpMethod(final String signUpMethod){
            this.signUpMethod = signUpMethod;
            return this;
        }

        public User build() {
            return new User(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        return userId != null && userId.equals(((User) o).getUserId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}


