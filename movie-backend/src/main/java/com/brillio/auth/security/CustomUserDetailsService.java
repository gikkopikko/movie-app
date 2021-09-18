package com.brillio.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.brillio.auth.model.Customer;
import com.brillio.auth.repository.CustomerRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {
	@Autowired
	CustomerRepository customerRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Customer customer = customerRepository.findByUsername(username).orElseThrow(
				() -> new UsernameNotFoundException("User not found with username or email : " + username));

		return UserPrincipal.create(customer);
	}

	@Transactional
	public UserDetails loadUserById(String id) {
		Customer customer = customerRepository.findById(id)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with id : " + id));

		return UserPrincipal.create(customer);
	}

}
