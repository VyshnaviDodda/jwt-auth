package com.jwt.demo;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class CustomUserDetailsService implements UserDetailsService {
	
	
	private UserRepository userRepo;
	
	private PasswordEncoder bcryptEncoder;
	
	@Autowired
	public CustomUserDetailsService(UserRepository userRepo, PasswordEncoder bcryptEncoder) {
		super();
		this.userRepo = userRepo;
		this.bcryptEncoder = bcryptEncoder;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException 
	{
//	List<SimpleGrantedAuthority> roles = null;
//	
//	if(username.equals("admin"))
//	{
//	roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
//	
//	return new User("admin", "$2y$12$I0Di/vfUL6nqwVbrvItFVOXA1L9OW9kLwe.1qDPhFzIJBpWl76PAe",
//				roles);
//	}
//	else if(username.equals("user"))
//	{
//	roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
//	
//	return new User("user", "$2y$12$VfZTUu/Yl5v7dAmfuxWU8uRfBKExHBWT1Iqi.s33727NoxHrbZ/h2",
//				roles);
//	}
//	throw new UsernameNotFoundException("User not found with username: " + username);
//		
   DAOUser user = userRepo.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with the name " + username);
        }

        List<SimpleGrantedAuthority> roles = Arrays.asList(new SimpleGrantedAuthority(user.getRole()));	        System.out.println("Username: " + user.getUsername());
	        System.out.println("Password: " + user.getPassword());
	        System.out.println("Roles: " + roles);
            System.out.println("Git testing.");
	        return new User(user.getUsername(), user.getPassword(), roles);
	}
	
	public DAOUser saveUser(UserDTO user) {
		DAOUser newUser = new DAOUser();
		newUser.setUsername(user.getUsername());
		newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
		newUser.setRole(user.getRole());
		return userRepo.save(newUser);
	}


}
