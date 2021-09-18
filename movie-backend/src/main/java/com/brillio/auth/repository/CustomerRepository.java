package com.brillio.auth.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.brillio.auth.model.Customer;

@Repository
public interface CustomerRepository extends MongoRepository<Customer, String> {
	Optional<Customer> findByUsername(String username);

	Boolean existsByUsername(String username);
}
