package com.jali.security.user;

// The purpose of the user repository is to communicate with the database
// Extend the JpaRepository to make this a repository

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// JpaRepository<class, id_type>
// This spring JpaRepository has many methods like save, findAll, findById.....

public interface UserRepository extends JpaRepository<User, Integer> {

    // Creating a method to find the users by their email

    // Optional is a container object from the Java 8 java.util package that may or may not contain a non-null value.
    // It represents an optional result of the search operation.
    Optional<User> findByEmail(String email);

}
