package com.brillio.auth.security;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.brillio.auth.model.Customer;

public class UserPrincipal implements UserDetails {
	private String id;
	private String name;
	private String username;
	private String password;
	private Collection<? extends GrantedAuthority> authorities;

	public UserPrincipal() {
		super();
	}

	public UserPrincipal(String id, String name, String username, String password,
			Collection<? extends GrantedAuthority> authorities) {
		super();
		this.id = id;
		this.name = name;
		this.username = username;
		this.password = password;
		this.authorities = authorities;
	}

	public static UserPrincipal create(Customer customer) {
		List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("user"));

		return new UserPrincipal(customer.getId(), customer.getName(), customer.getUsername(), customer.getPassword(),
				authorities);
	}

	public String getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
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

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		UserPrincipal that = (UserPrincipal) o;
		return Objects.equals(id, that.id);
	}

	@Override
	public int hashCode() {

		return Objects.hash(id);
	}

}
