package com.jali.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data // Provides the getters setters and more
@Builder // Build object in easy way (All args constructor is needed.)
@NoArgsConstructor
@AllArgsConstructor
@Entity // Make the user class an Entity
@Table(name = "_user") // Postresql has already a table called user hence we hv to change the name of the table
public class User implements UserDetails {
    // Here since the User object in the spring also implements UserDetails, you can create a seperate class like AppUser and extend that user for that class.
    // Or implements the UserDetails interface for your class like we do here.
    // "Hibernate" provides Object-Relational Persistence and Query service for applications.
    @Id // The unique identifier is the Integer Id
    @GeneratedValue // The Id is auto incremented. strategy default is auto. Then the hibernate will choose the best option for the increment of the id.
    private Integer id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    // There is a getPassword method in userDetails  interface to be implemented but we have this string password property and the Lombok @Data annotation which creates all those getters and setters.
    // But we deliberately override that method below.

    @Enumerated(EnumType.STRING) //Tell that this is an emun and the type of the enum version. Typically it is EnumType.Ordinal which use 0, 1, like wie for each element.
    private Role role;

    /*

    ABOUT THE "getAuthorities()" METHOD BELOW

    The return type: Collection<? extends GrantedAuthority>
        Means it returns a collection of objects that implements the GrantedAuthority or any of its subtypes.

        Inside the method, there is a line of code that creates a new "SimpleGrantedAuthority" object. The "SimpleGrantedAuthority" class is a simple implementation of the "GrantedAuthority" Interface provided by Spring Security framework.
        The constructor of "SimpleGrantedAuthority" requires a string parameter, which represent the authority or role granted to user. Here role.name() is used to ger the name of an enum constant called role. That role is an enum value that represent different roles or authorities
        that can be assigned to the users.
        The List.of() creates an immutable list containing the single SimpleGrantedAuthority object created. This list is returned by the getauthorities() methods.

    */

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // We need to provide a list of granted authorities granted authorities that means it return a list of ROLES. We can create an enum for it.
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

// When spring security starts and setup the application it will use an object called "UserDetails". It is an interface that contains a bunch of methods.
// Each time when you are working with spring security you need to provide this userDetails object in order to make the speing security life easier to use.
// So think like the user you create is already a spring user. So implements your user with the UserDetails class.